use anyhow::Result;
use colored::*;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use crate::cli::{VulnArgs, VulnCmd};

pub async fn run(args: VulnArgs) -> Result<()> {
    match args.cmd {
        VulnCmd::Scan { target, ports, timeout, output } => {
            scan_host(&target, &ports, timeout, output.as_deref())?;
        }
        VulnCmd::Netscan { cidr, timeout, output } => {
            scan_network(&cidr, timeout, output.as_deref()).await?;
        }
    }
    Ok(())
}

// ─── Estrutura de Finding ─────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub id: &'static str,
    pub title: String,
    pub host: String,
    pub port: u16,
    pub evidence: String,
    pub recommendation: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    fn label(&self) -> ColoredString {
        match self {
            Severity::Critical => "[CRITICO]".bright_red().bold(),
            Severity::High     => "[ALTO]   ".red().bold(),
            Severity::Medium   => "[MEDIO]  ".bright_yellow().bold(),
            Severity::Low      => "[BAIXO]  ".yellow(),
            Severity::Info     => "[INFO]   ".bright_blue(),
        }
    }
    fn score(&self) -> u8 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

// ─── Helpers de conexão ───────────────────────────────────────────────────

fn tcp_connect(host: &str, port: u16, timeout_ms: u64) -> Option<TcpStream> {
    let addr = format!("{}:{}", host, port);
    if let Ok(mut addrs) = addr.to_socket_addrs() {
        if let Some(sock) = addrs.next() {
            if let Ok(stream) = TcpStream::connect_timeout(&sock, Duration::from_millis(timeout_ms)) {
                let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
                return Some(stream);
            }
        }
    }
    None
}

fn tcp_send_recv(stream: &mut TcpStream, data: &[u8]) -> String {
    let _ = stream.write_all(data);
    let mut buf = vec![0u8; 4096];
    match stream.read(&mut buf) {
        Ok(n) => String::from_utf8_lossy(&buf[..n]).to_string(),
        Err(_) => String::new(),
    }
}

fn port_open(host: &str, port: u16, timeout_ms: u64) -> bool {
    tcp_connect(host, port, timeout_ms).is_some()
}

fn parse_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if let Some((s, e)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (s.parse::<u16>(), e.parse::<u16>()) {
                for p in s..=e { ports.push(p); }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

// ─── Checks individuais ───────────────────────────────────────────────────

fn check_ftp_anonymous(host: &str, timeout: u64) -> Option<Finding> {
    let mut stream = tcp_connect(host, 21, timeout)?;
    let banner = tcp_send_recv(&mut stream, b"");
    if !banner.contains("220") { return None; }

    let _ = stream.write_all(b"USER anonymous\r\n");
    let mut buf = vec![0u8; 512];
    let _ = stream.read(&mut buf);

    let _ = stream.write_all(b"PASS anonymous@\r\n");
    let mut buf2 = vec![0u8; 512];
    let n = stream.read(&mut buf2).unwrap_or(0);
    let resp = String::from_utf8_lossy(&buf2[..n]);

    if resp.contains("230") {
        Some(Finding {
            severity: Severity::Critical,
            id: "FTP-ANON",
            title: "FTP Anonymous Login habilitado".into(),
            host: host.into(),
            port: 21,
            evidence: format!("Login anônimo aceito: {}", resp.trim()),
            recommendation: "Desabilite o acesso anônimo FTP. Prefira SFTP/SCP.",
        })
    } else {
        None
    }
}

fn check_ftp_banner(host: &str, timeout: u64) -> Option<Finding> {
    let mut stream = tcp_connect(host, 21, timeout)?;
    let banner = tcp_send_recv(&mut stream, b"");
    if banner.is_empty() { return None; }

    // vsftpd 2.3.4 — backdoor famoso (CVE-2011-2523)
    if banner.contains("vsFTPd 2.3.4") {
        return Some(Finding {
            severity: Severity::Critical,
            id: "CVE-2011-2523",
            title: "vsftpd 2.3.4 — Backdoor conhecido".into(),
            host: host.into(),
            port: 21,
            evidence: format!("Banner: {}", banner.trim()),
            recommendation: "Atualize imediatamente o vsftpd. Esta versão tem backdoor que abre shell na porta 6200.",
        });
    }

    // Versão exposta no banner
    Some(Finding {
        severity: Severity::Low,
        id: "FTP-BANNER",
        title: "FTP expõe versão do servidor".into(),
        host: host.into(),
        port: 21,
        evidence: format!("Banner: {}", banner.lines().next().unwrap_or("").trim()),
        recommendation: "Configure o servidor FTP para ocultar a versão no banner.",
    })
}

fn check_telnet(host: &str, timeout: u64) -> Option<Finding> {
    if !port_open(host, 23, timeout) { return None; }
    Some(Finding {
        severity: Severity::Critical,
        id: "TELNET-OPEN",
        title: "Telnet aberto — protocolo sem criptografia".into(),
        host: host.into(),
        port: 23,
        evidence: "Porta 23/TCP acessível".into(),
        recommendation: "Desabilite Telnet imediatamente. Use SSH no lugar.",
    })
}

fn check_ssh_banner(host: &str, timeout: u64) -> Option<Finding> {
    let mut stream = tcp_connect(host, 22, timeout)?;
    let banner = tcp_send_recv(&mut stream, b"");
    if banner.is_empty() { return None; }

    let banner_line = banner.lines().next().unwrap_or("").trim().to_string();

    // Verifica versões antigas do OpenSSH
    if let Some(ver_str) = banner_line.strip_prefix("SSH-2.0-OpenSSH_") {
        let ver: f32 = ver_str.split_whitespace().next()
            .and_then(|v| v.split('p').next())
            .and_then(|v| v.parse().ok())
            .unwrap_or(99.0);

        if ver < 7.0 {
            return Some(Finding {
                severity: Severity::High,
                id: "SSH-OLD-VER",
                title: format!("OpenSSH versão antiga detectada: {}", ver_str.split_whitespace().next().unwrap_or("")),
                host: host.into(),
                port: 22,
                evidence: format!("Banner: {}", banner_line),
                recommendation: "Atualize o OpenSSH para versão 8.x ou superior.",
            });
        }
    }

    // SSH-1.x ainda ativo (protocolo obsoleto)
    if banner_line.starts_with("SSH-1.") {
        return Some(Finding {
            severity: Severity::Critical,
            id: "SSH-V1",
            title: "SSHv1 ativo — protocolo com vulnerabilidades graves".into(),
            host: host.into(),
            port: 22,
            evidence: format!("Banner: {}", banner_line),
            recommendation: "Desabilite SSHv1 completamente. Use apenas SSHv2.",
        });
    }

    // Info: versão do SSH
    Some(Finding {
        severity: Severity::Info,
        id: "SSH-BANNER",
        title: "SSH versão identificada".into(),
        host: host.into(),
        port: 22,
        evidence: format!("Banner: {}", banner_line),
        recommendation: "Mantenha o OpenSSH sempre atualizado.",
    })
}

fn check_http(host: &str, port: u16, timeout: u64) -> Vec<Finding> {
    let mut findings = Vec::new();

    let mut stream = match tcp_connect(host, port, timeout) {
        Some(s) => s,
        None => return findings,
    };

    let req = format!(
        "GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: Sentinela-VulnScanner/1.0\r\nConnection: close\r\n\r\n",
        host
    );
    let response = tcp_send_recv(&mut stream, req.as_bytes());
    if response.is_empty() { return findings; }

    let headers_lower = response.to_lowercase();
    let first_line = response.lines().next().unwrap_or("").trim().to_string();

    // ── Banner / Server version disclosure
    if let Some(server_line) = response.lines().find(|l| l.to_lowercase().starts_with("server:")) {
        let server_val = server_line[7..].trim();
        // Só alerta se tiver versão numérica no valor
        if server_val.chars().any(|c| c.is_ascii_digit()) {
            findings.push(Finding {
                severity: Severity::Low,
                id: "HTTP-SERVER-BANNER",
                title: "HTTP Server header expõe versão".into(),
                host: host.into(),
                port,
                evidence: format!("Header: {}", server_line.trim()),
                recommendation: "Configure o servidor para remover ou ofuscar o header 'Server'.",
            });

            // Apache versões antigas
            if server_val.to_lowercase().contains("apache/2.2") || server_val.to_lowercase().contains("apache/2.0") {
                findings.push(Finding {
                    severity: Severity::High,
                    id: "APACHE-OLD",
                    title: "Apache HTTP Server versão obsoleta".into(),
                    host: host.into(),
                    port,
                    evidence: format!("Versão detectada: {}", server_val),
                    recommendation: "Atualize o Apache para 2.4.x ou superior. Versões 2.2/2.0 não recebem patches.",
                });
            }

            // IIS versões antigas
            if server_val.to_lowercase().contains("iis/6") || server_val.to_lowercase().contains("iis/7") {
                findings.push(Finding {
                    severity: Severity::High,
                    id: "IIS-OLD",
                    title: "Microsoft IIS versão obsoleta".into(),
                    host: host.into(),
                    port,
                    evidence: format!("Versão detectada: {}", server_val),
                    recommendation: "Atualize o IIS para versão 10 (Windows Server 2016/2019).",
                });
            }
        }
    }

    // ── Security headers ausentes
    let sec_headers = [
        ("strict-transport-security", "MISS-HSTS",
         "Header HSTS ausente", Severity::Medium,
         "Adicione: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
        ("x-frame-options", "MISS-XFO",
         "Header X-Frame-Options ausente", Severity::Medium,
         "Adicione: X-Frame-Options: DENY (previne clickjacking)"),
        ("x-content-type-options", "MISS-XCTO",
         "Header X-Content-Type-Options ausente", Severity::Low,
         "Adicione: X-Content-Type-Options: nosniff"),
        ("content-security-policy", "MISS-CSP",
         "Content-Security-Policy ausente", Severity::Medium,
         "Implemente uma política CSP para prevenir XSS"),
        ("x-xss-protection", "MISS-XXP",
         "Header X-XSS-Protection ausente", Severity::Low,
         "Adicione: X-XSS-Protection: 1; mode=block"),
        ("referrer-policy", "MISS-RP",
         "Referrer-Policy ausente", Severity::Low,
         "Adicione: Referrer-Policy: strict-origin-when-cross-origin"),
    ];

    for (header, id, title, severity, rec) in &sec_headers {
        if !headers_lower.contains(&format!("{}:", header)) {
            findings.push(Finding {
                severity: severity.clone(),
                id,
                title: (*title).into(),
                host: host.into(),
                port,
                evidence: format!("Header '{}' não encontrado na resposta", header),
                recommendation: rec,
            });
        }
    }

    // ── HTTP TRACE method
    drop(stream);
    if let Some(mut s) = tcp_connect(host, port, timeout) {
        let trace_req = format!(
            "TRACE / HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
            host
        );
        let trace_resp = tcp_send_recv(&mut s, trace_req.as_bytes());
        if trace_resp.starts_with("HTTP/") && trace_resp.contains("200") {
            findings.push(Finding {
                severity: Severity::Medium,
                id: "HTTP-TRACE",
                title: "HTTP TRACE method habilitado (XST)".into(),
                host: host.into(),
                port,
                evidence: "Servidor respondeu 200 a requisição TRACE".into(),
                recommendation: "Desabilite o método TRACE no servidor. Apache: TraceEnable Off",
            });
        }
    }

    // ── HTTP sem HTTPS redirect (só porta 80)
    if port == 80 && !first_line.contains("301") && !first_line.contains("302") {
        if port_open(host, 443, timeout) {
            findings.push(Finding {
                severity: Severity::Medium,
                id: "HTTP-NO-REDIRECT",
                title: "HTTP não redireciona para HTTPS".into(),
                host: host.into(),
                port: 80,
                evidence: format!("Porta 80 responde: {}", first_line),
                recommendation: "Configure redirect 301 de HTTP para HTTPS.",
            });
        }
    }

    // ── Páginas de erro com info (common paths)
    let paths = ["/admin", "/phpmyadmin", "/.git/config", "/wp-admin", "/manager/html", "/.env"];
    for path in &paths {
        if let Some(mut s) = tcp_connect(host, port, timeout) {
            let req = format!(
                "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
                path, host
            );
            let resp = tcp_send_recv(&mut s, req.as_bytes());
            let first = resp.lines().next().unwrap_or("").trim();

            if first.contains("200") || first.contains("401") || first.contains("403") {
                let (severity, id, title) = match *path {
                    "/.git/config" => (Severity::Critical, "GIT-EXPOSED", "Repositório .git exposto"),
                    "/.env"        => (Severity::Critical, "ENV-EXPOSED", "Arquivo .env exposto"),
                    "/phpmyadmin"  => (Severity::High,     "PHPMYADMIN",  "phpMyAdmin acessível"),
                    "/wp-admin"    => (Severity::Medium,   "WPADMIN",     "WordPress admin exposto"),
                    "/manager/html"=> (Severity::High,     "TOMCAT-MGR",  "Tomcat Manager exposto"),
                    _              => (Severity::Medium,   "ADMIN-PATH",  "Painel administrativo exposto"),
                };
                findings.push(Finding {
                    severity,
                    id,
                    title: title.into(),
                    host: host.into(),
                    port,
                    evidence: format!("GET {} → {}", path, first),
                    recommendation: "Restrinja o acesso por IP ou remova o path exposto.",
                });
            }
        }
    }

    // ── Default credentials em interfaces web comuns
    let default_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "1234"),
        ("admin", ""),
        ("root", "root"),
        ("root", ""),
    ];

    let auth_paths = ["/", "/admin", "/login", "/cgi-bin/login.cgi"];
    'outer: for path in &auth_paths {
        for (user, pass) in &default_creds {
            if let Some(mut s) = tcp_connect(host, port, timeout) {
                let cred = base64_encode(&format!("{}:{}", user, pass));
                let req = format!(
                    "GET {} HTTP/1.0\r\nHost: {}\r\nAuthorization: Basic {}\r\nConnection: close\r\n\r\n",
                    path, host, cred
                );
                let resp = tcp_send_recv(&mut s, req.as_bytes());
                let first = resp.lines().next().unwrap_or("").trim().to_string();
                if first.contains("200") {
                    findings.push(Finding {
                        severity: Severity::Critical,
                        id: "DEFAULT-CREDS",
                        title: format!("Credencial padrão aceita: {}:{}", user, pass),
                        host: host.into(),
                        port,
                        evidence: format!("GET {} com {}: {} → 200 OK", path, user, cred),
                        recommendation: "Altere as credenciais padrão imediatamente.",
                    });
                    break 'outer;
                }
            }
        }
    }

    findings
}

fn base64_encode(input: &str) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(input)
}

fn check_redis(host: &str, timeout: u64) -> Option<Finding> {
    let mut stream = tcp_connect(host, 6379, timeout)?;
    let resp = tcp_send_recv(&mut stream, b"PING\r\n");
    if resp.contains("+PONG") {
        Some(Finding {
            severity: Severity::Critical,
            id: "REDIS-NOAUTH",
            title: "Redis sem autenticação".into(),
            host: host.into(),
            port: 6379,
            evidence: format!("Resposta ao PING: {}", resp.trim()),
            recommendation: "Configure 'requirepass' no redis.conf e restrinja acesso por firewall.",
        })
    } else {
        None
    }
}

fn check_mongodb(host: &str, timeout: u64) -> Option<Finding> {
    // Tenta conectar e verificar se aceita query sem auth
    // MongoDB responde com dados binários — apenas checar se porta aceita conexão
    // e enviar um ismaster wire protocol message
    let mut stream = tcp_connect(host, 27017, timeout)?;

    // Wire protocol: OP_QUERY para isMaster
    let msg: &[u8] = &[
        0x3a, 0x00, 0x00, 0x00, // messageLength = 58
        0x01, 0x00, 0x00, 0x00, // requestID
        0x00, 0x00, 0x00, 0x00, // responseTo
        0xd4, 0x07, 0x00, 0x00, // opCode = 2004 (OP_QUERY)
        0x00, 0x00, 0x00, 0x00, // flags
        0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x24, 0x63, 0x6d, 0x64, 0x00, // "admin.$cmd\0"
        0x00, 0x00, 0x00, 0x00, // numberToSkip
        0x01, 0x00, 0x00, 0x00, // numberToReturn
        // BSON doc: {isMaster: 1}
        0x13, 0x00, 0x00, 0x00,
        0x10, 0x69, 0x73, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00,
    ];

    let _ = stream.write_all(msg);
    let mut buf = vec![0u8; 256];
    if let Ok(n) = stream.read(&mut buf) {
        if n > 0 {
            return Some(Finding {
                severity: Severity::Critical,
                id: "MONGO-NOAUTH",
                title: "MongoDB acessível sem autenticação".into(),
                host: host.into(),
                port: 27017,
                evidence: format!("Servidor respondeu {} bytes sem credenciais", n),
                recommendation: "Ative autenticação no MongoDB e restrinja acesso por IP/firewall.",
            });
        }
    }
    None
}

fn check_smb_null(host: &str, timeout: u64) -> Option<Finding> {
    // SMB na porta 445 — verifica se está aberta (null session via Samba é complexo)
    // Apenas flagramos SMB aberto como finding informativo
    if !port_open(host, 445, timeout) { return None; }

    Some(Finding {
        severity: Severity::Medium,
        id: "SMB-EXPOSED",
        title: "SMB (porta 445) exposto na rede".into(),
        host: host.into(),
        port: 445,
        evidence: "Porta 445/TCP acessível".into(),
        recommendation: "Restrinja SMB por firewall. Nunca exponha SMB à internet (EternalBlue/WannaCry).",
    })
}

fn check_vnc(host: &str, timeout: u64) -> Option<Finding> {
    let mut stream = tcp_connect(host, 5900, timeout)?;
    let banner = tcp_send_recv(&mut stream, b"");
    if banner.is_empty() { return None; }

    let sev = if banner.contains("RFB 003.003") || banner.contains("RFB 003.007") {
        Severity::High
    } else {
        Severity::Medium
    };

    Some(Finding {
        severity: sev,
        id: "VNC-EXPOSED",
        title: "VNC exposto na rede".into(),
        host: host.into(),
        port: 5900,
        evidence: format!("Banner: {}", banner.trim()),
        recommendation: "Use túnel SSH para VNC. Nunca exponha VNC diretamente à internet.",
    })
}

fn check_mysql_anon(host: &str, port: u16, timeout: u64) -> Option<Finding> {
    // MySQL/MariaDB — lê handshake inicial para identificar versão
    let mut stream = tcp_connect(host, port, timeout)?;
    let mut buf = vec![0u8; 128];
    let n = stream.read(&mut buf).unwrap_or(0);
    if n < 5 { return None; }

    // Pacote MySQL começa com length (3 bytes) + seq (1 byte) + protocol version (1 byte = 0x0a)
    if buf[4] == 0x0a {
        // Extrai string de versão (null-terminated após byte 5)
        let version: String = buf[5..].iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();

        let finding = Finding {
            severity: Severity::Low,
            id: "MYSQL-BANNER",
            title: format!("MySQL/MariaDB versão exposta: {}", version),
            host: host.into(),
            port,
            evidence: format!("Handshake MySQL: versão {}", version),
            recommendation: "Restrinja acesso ao MySQL por IP. Nunca exponha à internet.",
        };

        // Versões antigas com vulnerabilidades
        if version.starts_with("5.0") || version.starts_with("5.1") || version.starts_with("5.5") {
            return Some(Finding {
                severity: Severity::High,
                id: "MYSQL-OLD",
                title: format!("MySQL versão antiga: {}", version),
                host: host.into(),
                port,
                evidence: format!("Versão detectada via handshake: {}", version),
                recommendation: "Atualize o MySQL para 8.0+. Versões 5.x não recebem patches de segurança.",
            });
        }
        return Some(finding);
    }
    None
}

// ─── Scan de host completo ────────────────────────────────────────────────

fn scan_host(target: &str, ports_str: &str, timeout: u64, output: Option<&str>) -> Result<()> {
    let ports = parse_ports(ports_str);

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Vulnerability Scan:".bright_white().bold(),
        target.bright_yellow()
    );
    println!("  Verificando {} portas | timeout {}ms",
        ports.len().to_string().bright_yellow(),
        timeout.to_string().bright_yellow()
    );
    println!("{}", "─".repeat(70).bright_black());
    println!();

    let mut all_findings: Vec<Finding> = Vec::new();

    // Roda cada check baseado nas portas abertas
    for &port in &ports {
        if !port_open(target, port, timeout) { continue; }

        print!("  {} Verificando {}:{} ... ",
            "▸".bright_cyan(),
            target.bright_white(),
            port.to_string().bright_yellow()
        );

        let mut findings = Vec::new();

        match port {
            21  => {
                if let Some(f) = check_ftp_anonymous(target, timeout) { findings.push(f); }
                if let Some(f) = check_ftp_banner(target, timeout) { findings.push(f); }
            }
            22  => {
                if let Some(f) = check_ssh_banner(target, timeout) { findings.push(f); }
            }
            23  => {
                if let Some(f) = check_telnet(target, timeout) { findings.push(f); }
            }
            80 | 8080 | 8008 | 9080 => {
                findings.extend(check_http(target, port, timeout));
            }
            443 | 8443 | 9443 => {
                findings.push(Finding {
                    severity: Severity::Info,
                    id: "HTTPS-OPEN",
                    title: "HTTPS acessível".into(),
                    host: target.into(),
                    port,
                    evidence: format!("Porta {}/TCP aberta", port),
                    recommendation: "Verifique certificado, versão TLS e cipher suites.",
                });
            }
            445 => {
                if let Some(f) = check_smb_null(target, timeout) { findings.push(f); }
            }
            3306 => {
                if let Some(f) = check_mysql_anon(target, 3306, timeout) { findings.push(f); }
            }
            5900 => {
                if let Some(f) = check_vnc(target, timeout) { findings.push(f); }
            }
            6379 => {
                if let Some(f) = check_redis(target, timeout) { findings.push(f); }
            }
            9000 | 27017 => {
                if port == 27017 {
                    if let Some(f) = check_mongodb(target, timeout) { findings.push(f); }
                } else {
                    findings.push(Finding {
                        severity: Severity::Low,
                        id: "IOT-PORT",
                        title: format!("Porta IoT/dispositivo {} aberta", port),
                        host: target.into(),
                        port,
                        evidence: format!("Porta {}/TCP acessível", port),
                        recommendation: "Identifique o serviço e restrinja acesso por firewall.",
                    });
                }
            }
            _ => {
                findings.push(Finding {
                    severity: Severity::Info,
                    id: "PORT-OPEN",
                    title: format!("Porta {} aberta", port),
                    host: target.into(),
                    port,
                    evidence: format!("Porta {}/TCP acessível", port),
                    recommendation: "Identifique o serviço e verifique se é necessário.",
                });
            }
        }

        if findings.is_empty() {
            println!("{}", "OK".bright_green());
        } else {
            let max_sev = findings.iter().map(|f| f.severity.score()).max().unwrap_or(0);
            let label = match max_sev {
                5 => "CRITICO".bright_red().bold(),
                4 => "ALTO".red().bold(),
                3 => "MEDIO".bright_yellow().bold(),
                2 => "BAIXO".yellow(),
                _ => "INFO".bright_blue(),
            };
            println!("{} ({} findings)", label, findings.len());
        }

        all_findings.extend(findings);
    }

    // Exibe relatório
    print_report(&all_findings, target);

    // Export JSON
    if let Some(path) = output {
        export_json(&all_findings, target, path)?;
        println!("\n{} Relatório exportado: {}", "[+]".bright_green().bold(), path.bright_yellow());
    }

    Ok(())
}

fn print_report(findings: &[Finding], target: &str) {
    println!("\n{}", "─".repeat(70).bright_black());
    println!("{} {} {}",
        "RELATÓRIO DE VULNERABILIDADES".bright_white().bold(),
        "—".bright_black(),
        target.bright_yellow()
    );
    println!("{}", "─".repeat(70).bright_black());

    if findings.is_empty() {
        println!("\n{} Nenhuma vulnerabilidade detectada nos checks realizados.",
            "[+]".bright_green().bold());
        println!("  {}", "Isso não significa ausência total de vulnerabilidades.".bright_black().italic());
        return;
    }

    // Ordena por severidade decrescente
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| b.severity.score().cmp(&a.severity.score()));

    for f in &sorted {
        println!("\n{} {} {}",
            f.severity.label(),
            format!("[{}]", f.id).bright_black(),
            f.title.bright_white().bold()
        );
        println!("  {} {}:{}", "Host    :".bright_black(), f.host.bright_yellow(), f.port.to_string().bright_yellow());
        println!("  {} {}", "Evidência:".bright_black(), f.evidence.bright_white());
        println!("  {} {}", "Correção :".bright_black(), f.recommendation.bright_green());
    }

    println!("\n{}", "─".repeat(70).bright_black());

    // Contagem por severidade
    let mut counts = [0usize; 5];
    for f in findings {
        counts[f.severity.score() as usize - 1] += 1;
    }

    println!("  {} total  |  {} {}  {} {}  {} {}  {} {}  {} {}",
        findings.len().to_string().bright_white().bold(),
        counts[4].to_string().bright_red().bold(), "Críticos".bright_red(),
        counts[3].to_string().red(), "Altos".red(),
        counts[2].to_string().bright_yellow(), "Médios".bright_yellow(),
        counts[1].to_string().yellow(), "Baixos".yellow(),
        counts[0].to_string().bright_blue(), "Info".bright_blue(),
    );
    println!("{}", "─".repeat(70).bright_black());
}

fn export_json(findings: &[Finding], target: &str, path: &str) -> Result<()> {
    use std::io::Write;

    let json = serde_json::json!({
        "target": target,
        "total": findings.len(),
        "findings": findings.iter().map(|f| serde_json::json!({
            "severity": format!("{:?}", f.severity),
            "id": f.id,
            "title": f.title,
            "host": f.host,
            "port": f.port,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        })).collect::<Vec<_>>(),
    });

    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;
    Ok(())
}

// ─── Scan de rede /CIDR ───────────────────────────────────────────────────

async fn scan_network(cidr: &str, timeout: u64, output: Option<&str>) -> Result<()> {
    use std::net::ToSocketAddrs;
    use tokio::task;
    use std::sync::{Arc, Mutex};

    let ips = expand_cidr(cidr)?;
    let total = ips.len();

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Network Vuln Scan:".bright_white().bold(),
        cidr.bright_yellow()
    );
    println!("  {} hosts a verificar | timeout {}ms",
        total.to_string().bright_yellow(),
        timeout.to_string().bright_yellow()
    );
    println!("{}", "─".repeat(70).bright_black());
    println!();

    let default_ports = "21,22,23,80,443,445,3306,5900,6379,8080,27017";
    let ports = parse_ports(default_ports);

    let all_findings: Arc<Mutex<Vec<Finding>>> = Arc::new(Mutex::new(Vec::new()));
    let sem = Arc::new(tokio::sync::Semaphore::new(20));

    let mut handles = Vec::new();

    for ip in ips {
        // Verifica se host está vivo primeiro
        let is_up = {
            let ip_clone = ip.clone();
            let p = ports.clone();
            task::spawn_blocking(move || {
                p.iter().any(|&port| {
                    let addr = format!("{}:{}", ip_clone, port);
                    if let Ok(mut addrs) = addr.to_socket_addrs() {
                        if let Some(sock) = addrs.next() {
                            return TcpStream::connect_timeout(&sock, Duration::from_millis(300)).is_ok();
                        }
                    }
                    false
                })
            }).await.unwrap_or(false)
        };

        if !is_up { continue; }

        let findings_clone = Arc::clone(&all_findings);
        let sem_clone = Arc::clone(&sem);
        let ip_clone = ip.clone();
        let ports_str = default_ports.to_string();

        let handle = task::spawn(async move {
            let _permit = sem_clone.acquire().await.unwrap();

            println!("  {} Scanning {}...", "▸".bright_cyan(), ip_clone.bright_yellow());

            let findings = task::spawn_blocking(move || {
                let mut fs = Vec::new();
                let pts = parse_ports(&ports_str);
                for &port in &pts {
                    if !port_open(&ip_clone, port, timeout) { continue; }
                    match port {
                        21  => {
                            if let Some(f) = check_ftp_anonymous(&ip_clone, timeout) { fs.push(f); }
                            if let Some(f) = check_ftp_banner(&ip_clone, timeout) { fs.push(f); }
                        }
                        22  => { if let Some(f) = check_ssh_banner(&ip_clone, timeout) { fs.push(f); } }
                        23  => { if let Some(f) = check_telnet(&ip_clone, timeout) { fs.push(f); } }
                        80 | 8080 => { fs.extend(check_http(&ip_clone, port, timeout)); }
                        445 => { if let Some(f) = check_smb_null(&ip_clone, timeout) { fs.push(f); } }
                        3306 => { if let Some(f) = check_mysql_anon(&ip_clone, port, timeout) { fs.push(f); } }
                        5900 => { if let Some(f) = check_vnc(&ip_clone, timeout) { fs.push(f); } }
                        6379 => { if let Some(f) = check_redis(&ip_clone, timeout) { fs.push(f); } }
                        27017 => { if let Some(f) = check_mongodb(&ip_clone, timeout) { fs.push(f); } }
                        _ => {}
                    }
                }
                fs
            }).await.unwrap_or_default();

            let count = findings.len();
            if count > 0 {
                let max = findings.iter().map(|f| f.severity.score()).max().unwrap_or(0);
                let label = match max {
                    5 => "CRITICO".bright_red().bold().to_string(),
                    4 => "ALTO".red().bold().to_string(),
                    3 => "MEDIO".bright_yellow().bold().to_string(),
                    _ => "BAIXO".yellow().to_string(),
                };
                println!("  {} {} — {} findings ({})", "[!]".bright_red(), ip.bright_white().bold(), count, label);
            }

            findings_clone.lock().unwrap().extend(findings);
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let findings = all_findings.lock().unwrap().clone();

    println!("\n{}", "═".repeat(70).bright_black());
    println!("{}", "  SUMÁRIO NETWORK VULN SCAN".bright_white().bold());

    // Agrupa por host
    let mut by_host: std::collections::HashMap<String, Vec<&Finding>> = std::collections::HashMap::new();
    for f in &findings {
        by_host.entry(f.host.clone()).or_default().push(f);
    }

    use comfy_table::{Table, Cell, Color, Attribute};
    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Host").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Críticos").add_attribute(Attribute::Bold).fg(Color::Red),
        Cell::new("Altos").add_attribute(Attribute::Bold).fg(Color::Yellow),
        Cell::new("Médios").add_attribute(Attribute::Bold).fg(Color::Yellow),
        Cell::new("Top Finding").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    let mut hosts: Vec<&String> = by_host.keys().collect();
    hosts.sort();

    for host in hosts {
        let hf = &by_host[host];
        let crit = hf.iter().filter(|f| f.severity == Severity::Critical).count();
        let high = hf.iter().filter(|f| f.severity == Severity::High).count();
        let med  = hf.iter().filter(|f| f.severity == Severity::Medium).count();
        let top  = hf.iter().max_by_key(|f| f.severity.score())
            .map(|f| f.title.chars().take(40).collect::<String>())
            .unwrap_or_default();

        table.add_row(vec![
            Cell::new(host).fg(Color::White),
            Cell::new(if crit > 0 { crit.to_string() } else { "-".into() })
                .fg(if crit > 0 { Color::Red } else { Color::DarkGrey }),
            Cell::new(if high > 0 { high.to_string() } else { "-".into() })
                .fg(if high > 0 { Color::Yellow } else { Color::DarkGrey }),
            Cell::new(if med > 0 { med.to_string() } else { "-".into() })
                .fg(if med > 0 { Color::Yellow } else { Color::DarkGrey }),
            Cell::new(top).fg(Color::White),
        ]);
    }

    println!("{}", table);
    println!("  Total de findings: {}", findings.len().to_string().bright_red().bold());

    if let Some(path) = output {
        export_json_network(&findings, cidr, path)?;
        println!("{} Relatório exportado: {}", "[+]".bright_green().bold(), path.bright_yellow());
    }

    Ok(())
}

fn export_json_network(findings: &[Finding], cidr: &str, path: &str) -> Result<()> {
    use std::io::Write;
    let json = serde_json::json!({
        "network": cidr,
        "total": findings.len(),
        "findings": findings.iter().map(|f| serde_json::json!({
            "severity": format!("{:?}", f.severity),
            "id": f.id,
            "title": f.title,
            "host": f.host,
            "port": f.port,
            "evidence": f.evidence,
            "recommendation": f.recommendation,
        })).collect::<Vec<_>>(),
    });
    let mut file = std::fs::File::create(path)?;
    file.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;
    Ok(())
}

fn expand_cidr(cidr: &str) -> Result<Vec<String>> {
    if let Some((base, prefix)) = cidr.split_once('/') {
        let prefix: u32 = prefix.parse()?;
        let parts: Vec<u32> = base.split('.').map(|p| p.parse::<u32>().unwrap_or(0)).collect();
        if parts.len() != 4 { anyhow::bail!("CIDR inválido"); }
        let base_ip: u32 = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
        let mask: u32 = if prefix == 0 { 0 } else { !0u32 << (32 - prefix) };
        let network = base_ip & mask;
        let broadcast = network | !mask;
        let mut ips = Vec::new();
        for ip_u32 in (network + 1)..broadcast {
            ips.push(format!("{}.{}.{}.{}",
                (ip_u32 >> 24) & 0xFF, (ip_u32 >> 16) & 0xFF,
                (ip_u32 >> 8) & 0xFF, ip_u32 & 0xFF));
        }
        Ok(ips)
    } else {
        Ok(vec![cidr.to_string()])
    }
}
