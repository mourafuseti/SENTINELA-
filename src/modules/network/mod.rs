use anyhow::Result;
use colored::*;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::sync::{Arc, Mutex};
use tokio::task;

use crate::cli::{NetworkArgs, NetworkCmd};

pub async fn run(args: NetworkArgs) -> Result<()> {
    match args.cmd {
        NetworkCmd::Scan { target, ports, timeout, threads } => {
            scan_ports(&target, &ports, timeout, threads).await?;
        }
        NetworkCmd::Dns { target, all } => {
            dns_lookup(&target, all).await?;
        }
        NetworkCmd::Sweep { cidr, timeout } => {
            ping_sweep(&cidr, timeout).await?;
        }
        NetworkCmd::Banner { target, port } => {
            grab_banner(&target, port).await?;
        }
        NetworkCmd::Netscan { cidr, ports, timeout, threads, output } => {
            netscan(&cidr, &ports, timeout, threads, output.as_deref()).await?;
        }
    }
    Ok(())
}

// ─── Port Scanner ──────────────────────────────────────────────────────────

fn parse_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in ports_str.split(',') {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.parse::<u16>(), end.parse::<u16>()) {
                for p in s..=e {
                    ports.push(p);
                }
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ports.push(p);
        }
    }
    ports
}

fn get_service_name(port: u16) -> &'static str {
    match port {
        21    => "FTP",
        22    => "SSH",
        23    => "Telnet",
        25    => "SMTP",
        53    => "DNS",
        80    => "HTTP",
        110   => "POP3",
        111   => "RPC",
        135   => "MSRPC",
        139   => "NetBIOS",
        143   => "IMAP",
        443   => "HTTPS",
        445   => "SMB",
        554   => "RTSP",
        993   => "IMAPS",
        995   => "POP3S",
        1080  => "SOCKS",
        1433  => "MSSQL",
        1521  => "Oracle",
        1900  => "UPnP",
        2222  => "SSH-alt",
        2968  => "enpp",
        3306  => "MySQL",
        3389  => "RDP",
        5000  => "UPnP/dev",
        5432  => "PostgreSQL",
        5900  => "VNC",
        6379  => "Redis",
        7070  => "RealServer",
        8008  => "HTTP-alt",
        8009  => "AJP",
        8080  => "HTTP-proxy",
        8443  => "HTTPS-alt",
        8888  => "HTTP-dev",
        9000  => "HTTP-IoT",
        9080  => "HTTP-alt2",
        9090  => "HTTP-mgmt",
        9200  => "Elasticsearch",
        27017 => "MongoDB",
        62078 => "iPhone-sync",
        _     => "unknown",
    }
}

async fn scan_ports(target: &str, ports_str: &str, timeout_ms: u64, max_threads: usize) -> Result<()> {
    let ports = parse_ports(ports_str);
    let total = ports.len();

    println!("{} {} {} {}",
        "[*]".bright_blue().bold(),
        "Scanning".bright_white(),
        target.bright_yellow(),
        format!("| {} ports | {}ms timeout | {} threads", total, timeout_ms, max_threads).bright_black()
    );
    println!("{}", "─".repeat(60).bright_black());

    let open_ports: Arc<Mutex<Vec<(u16, &'static str)>>> = Arc::new(Mutex::new(Vec::new()));
    let target_owned = target.to_string();
    let timeout = Duration::from_millis(timeout_ms);

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_threads));
    let mut handles = Vec::new();

    for port in ports {
        let target_clone = target_owned.clone();
        let open_clone = Arc::clone(&open_ports);
        let sem = Arc::clone(&semaphore);

        let handle = task::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let addr = format!("{}:{}", target_clone, port);

            let is_open = task::spawn_blocking(move || {
                if let Ok(mut addrs) = addr.to_socket_addrs() {
                    if let Some(sock) = addrs.next() {
                        return TcpStream::connect_timeout(&sock, timeout).is_ok();
                    }
                }
                false
            }).await.unwrap_or(false);

            if is_open {
                let service = get_service_name(port);
                println!("  {} {} {}",
                    format!("{:>5}/tcp", port).bright_green().bold(),
                    "open".green(),
                    service.bright_cyan()
                );
                open_clone.lock().unwrap().push((port, service));
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let open = open_ports.lock().unwrap();
    println!("{}", "─".repeat(60).bright_black());
    println!("{} {} portas abertas encontradas em {}",
        "[+]".bright_green().bold(),
        open.len().to_string().bright_yellow().bold(),
        target.bright_white()
    );

    Ok(())
}

// ─── DNS Lookup ────────────────────────────────────────────────────────────

async fn dns_lookup(target: &str, _all: bool) -> Result<()> {
    use hickory_resolver::lookup::MxLookup;
    use hickory_resolver::lookup::NsLookup;
    use hickory_resolver::lookup::TxtLookup;
    use hickory_resolver::lookup_ip::LookupIp;

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "DNS Recon:".bright_white(),
        target.bright_yellow()
    );
    println!("{}", "─".repeat(60).bright_black());

    let resolver = hickory_resolver::Resolver::builder_tokio()?.build();

    // Registros A / IPv4
    print_dns_section("A (IPv4)");
    match resolver.lookup_ip(target).await {
        Ok(response) => {
            let response: LookupIp = response;
            let mut found = false;
            for ip in response.iter() {
                if ip.is_ipv4() {
                    println!("  {} {}", "→".bright_green(), ip.to_string().bright_white());
                    found = true;
                }
            }
            if !found { println!("  {}", "Nenhum registro encontrado".bright_black()); }
        }
        Err(_) => println!("  {}", "Nenhum registro encontrado".bright_black()),
    }

    // Registros AAAA / IPv6
    print_dns_section("AAAA (IPv6)");
    match resolver.lookup_ip(target).await {
        Ok(response) => {
            let response: LookupIp = response;
            let mut found = false;
            for ip in response.iter() {
                if ip.is_ipv6() {
                    println!("  {} {}", "→".bright_green(), ip.to_string().bright_white());
                    found = true;
                }
            }
            if !found { println!("  {}", "Nenhum registro encontrado".bright_black()); }
        }
        Err(_) => println!("  {}", "Nenhum registro encontrado".bright_black()),
    }

    // MX
    print_dns_section("MX (Mail)");
    match resolver.mx_lookup(target).await {
        Ok(response) => {
            let response: MxLookup = response;
            for mx in response.iter() {
                println!("  {} {} (prio: {})",
                    "→".bright_green(),
                    mx.exchange().to_string().bright_white(),
                    mx.preference().to_string().bright_yellow()
                );
            }
        }
        Err(_) => println!("  {}", "Nenhum registro encontrado".bright_black()),
    }

    // NS
    print_dns_section("NS (Nameservers)");
    match resolver.ns_lookup(target).await {
        Ok(response) => {
            let response: NsLookup = response;
            for ns in response.iter() {
                println!("  {} {}", "→".bright_green(), ns.to_string().bright_white());
            }
        }
        Err(_) => println!("  {}", "Nenhum registro encontrado".bright_black()),
    }

    // TXT
    print_dns_section("TXT");
    match resolver.txt_lookup(target).await {
        Ok(response) => {
            let response: TxtLookup = response;
            for txt in response.iter() {
                println!("  {} {}", "→".bright_green(), txt.to_string().bright_white());
            }
        }
        Err(_) => println!("  {}", "Nenhum registro encontrado".bright_black()),
    }

    println!("{}", "─".repeat(60).bright_black());
    println!("{} DNS recon concluído", "[+]".bright_green().bold());

    Ok(())
}

fn print_dns_section(name: &str) {
    println!("\n  {} {}", "▸".bright_blue(), name.bright_cyan().bold());
}

// ─── Ping Sweep ────────────────────────────────────────────────────────────

async fn ping_sweep(cidr: &str, timeout_ms: u64) -> Result<()> {
    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Ping sweep:".bright_white(),
        cidr.bright_yellow()
    );
    println!("{}", "─".repeat(60).bright_black());

    let ips = expand_cidr(cidr)?;
    let total = ips.len();
    let alive: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let timeout = Duration::from_millis(timeout_ms);

    let semaphore = Arc::new(tokio::sync::Semaphore::new(100));
    let mut handles = Vec::new();

    for ip in ips {
        let alive_clone = Arc::clone(&alive);
        let sem = Arc::clone(&semaphore);
        let ip_str = ip.clone();

        let handle = task::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            // Testa via TCP na porta 80 ou 443 como proxy de "alive"
            let is_up = task::spawn_blocking(move || {
                for port in [80u16, 443, 22, 445, 8080] {
                    let addr = format!("{}:{}", ip_str, port);
                    if let Ok(addrs) = addr.to_socket_addrs() {
                        for sock in addrs {
                            if TcpStream::connect_timeout(&sock, timeout).is_ok() {
                                return true;
                            }
                        }
                    }
                }
                false
            }).await.unwrap_or(false);

            if is_up {
                println!("  {} {} {}", "[UP]".bright_green().bold(), ip.bright_white(), "host ativo".bright_black());
                alive_clone.lock().unwrap().push(ip.clone());
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }

    let up = alive.lock().unwrap();
    println!("{}", "─".repeat(60).bright_black());
    println!("{} {}/{} hosts ativos", "[+]".bright_green().bold(), up.len(), total);

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
                (ip_u32 >> 24) & 0xFF,
                (ip_u32 >> 16) & 0xFF,
                (ip_u32 >> 8) & 0xFF,
                ip_u32 & 0xFF
            ));
        }
        Ok(ips)
    } else {
        Ok(vec![cidr.to_string()])
    }
}

// ─── Banner Grabbing ───────────────────────────────────────────────────────

async fn grab_banner(target: &str, port: u16) -> Result<()> {
    use std::io::{Read, Write};

    println!("{} {} {}:{}",
        "[*]".bright_blue().bold(),
        "Banner grab:".bright_white(),
        target.bright_yellow(),
        port.to_string().bright_yellow()
    );

    let addr = format!("{}:{}", target, port);
    let sock_addr: SocketAddr = addr.to_socket_addrs()?.next()
        .ok_or_else(|| anyhow::anyhow!("Não foi possível resolver o endereço"))?;

    match TcpStream::connect_timeout(&sock_addr, Duration::from_secs(3)) {
        Ok(mut stream) => {
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;

            // Envia um probe HTTP simples para portas web
            if port == 80 || port == 8080 || port == 8888 {
                let req = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", target);
                let _ = stream.write_all(req.as_bytes());
            }

            let mut banner = vec![0u8; 2048];
            match stream.read(&mut banner) {
                Ok(n) if n > 0 => {
                    let text = String::from_utf8_lossy(&banner[..n]);
                    println!("{}", "─".repeat(60).bright_black());
                    println!("{}", text.trim().bright_white());
                    println!("{}", "─".repeat(60).bright_black());
                    println!("{} Banner capturado ({} bytes)", "[+]".bright_green().bold(), n);
                }
                _ => println!("{} Sem resposta ou porta fechada", "[!]".bright_yellow().bold()),
            }
        }
        Err(e) => {
            println!("{} Falha na conexão: {}", "[-]".bright_red().bold(), e);
        }
    }

    Ok(())
}

// ─── Network Scan /CIDR ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct HostResult {
    ip: String,
    open_ports: Vec<(u16, &'static str)>,
}

async fn netscan(
    cidr: &str,
    ports_str: &str,
    timeout_ms: u64,
    max_threads: usize,
    output: Option<&str>,
) -> Result<()> {
    use indicatif::{ProgressBar, ProgressStyle, MultiProgress};

    let ips = expand_cidr(cidr)?;
    let ports = parse_ports(ports_str);
    let total_hosts = ips.len();
    let total_ports = ports.len();

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Network Scan".bright_white().bold(),
        cidr.bright_yellow()
    );
    println!("  {} hosts | {} portas por host | {}ms timeout | {} threads/host",
        total_hosts.to_string().bright_yellow(),
        total_ports.to_string().bright_yellow(),
        timeout_ms.to_string().bright_yellow(),
        max_threads.to_string().bright_yellow()
    );
    println!("{}", "─".repeat(65).bright_black());

    // ── Fase 1: descoberta de hosts vivos ─────────────────────────────
    println!("\n{} {}", "►".bright_cyan().bold(), "Fase 1: descoberta de hosts vivos...".bright_white());

    let mp = MultiProgress::new();
    let pb_discover = mp.add(ProgressBar::new(total_hosts as u64));
    pb_discover.set_style(ProgressStyle::default_bar()
        .template("  [{bar:45.cyan/blue}] {pos}/{len} hosts  ({eta})")
        .unwrap()
        .progress_chars("=>-"));

    let alive_hosts: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let sem_discover = Arc::new(tokio::sync::Semaphore::new(100));
    let timeout = Duration::from_millis(timeout_ms);

    // Portas de fallback TCP — amplo para cobrir IoT, câmeras, celulares, roteadores
    let tcp_fallback: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        554, 1080, 1900, 2968, 3306, 3389, 5000, 5432, 5900,
        7070, 8008, 8009, 8080, 8443, 8888, 9000, 9080, 9090,
        62078,
    ];

    let mut handles = Vec::new();
    for ip in ips {
        let alive_clone = Arc::clone(&alive_hosts);
        let sem = Arc::clone(&sem_discover);
        let pb = pb_discover.clone();
        let fallback = tcp_fallback.clone();

        let handle = task::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let ip_str = ip.clone();

            let is_up = task::spawn_blocking(move || {
                // Método 1: ICMP ping (rápido, funciona sem root em rede local)
                if let Ok(output) = std::process::Command::new("ping")
                    .args(["-c", "1", "-W", "1", &ip_str])
                    .output()
                {
                    if output.status.success() {
                        return true;
                    }
                }

                // Método 2: TCP probe amplo — cobre IoT, câmeras, celulares
                // Usa timeout menor para ser rápido na varredura
                let tcp_timeout = Duration::from_millis(300);
                for port in fallback {
                    let addr = format!("{}:{}", ip_str, port);
                    if let Ok(mut addrs) = addr.to_socket_addrs() {
                        if let Some(sock) = addrs.next() {
                            if TcpStream::connect_timeout(&sock, tcp_timeout).is_ok() {
                                return true;
                            }
                        }
                    }
                }
                false
            }).await.unwrap_or(false);

            pb.inc(1);
            if is_up {
                alive_clone.lock().unwrap().push(ip);
            }
        });
        handles.push(handle);
    }

    for h in handles {
        let _ = h.await;
    }
    pb_discover.finish_and_clear();

    let alive: Vec<String> = alive_hosts.lock().unwrap().clone();

    if alive.is_empty() {
        println!("\n{} Nenhum host ativo encontrado em {}", "[-]".bright_yellow().bold(), cidr);
        return Ok(());
    }

    println!("  {} {} hosts ativos encontrados\n",
        "[+]".bright_green().bold(),
        alive.len().to_string().bright_green().bold()
    );

    // ── Fase 2: port scan em cada host vivo ──────────────────────────
    println!("{} {}", "►".bright_cyan().bold(), "Fase 2: varrendo portas de cada host...".bright_white());

    let pb_scan = mp.add(ProgressBar::new(alive.len() as u64));
    pb_scan.set_style(ProgressStyle::default_bar()
        .template("  [{bar:45.green/black}] {pos}/{len} hosts escaneados")
        .unwrap()
        .progress_chars("=>-"));

    let results: Arc<Mutex<Vec<HostResult>>> = Arc::new(Mutex::new(Vec::new()));

    for ip in &alive {
        let open_ports: Arc<Mutex<Vec<(u16, &'static str)>>> = Arc::new(Mutex::new(Vec::new()));
        let sem_ports = Arc::new(tokio::sync::Semaphore::new(max_threads));
        let mut port_handles = Vec::new();

        for &port in &ports {
            let target_clone = ip.clone();
            let open_clone = Arc::clone(&open_ports);
            let sem = Arc::clone(&sem_ports);

            let handle = task::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                let addr = format!("{}:{}", target_clone, port);

                let is_open = task::spawn_blocking(move || {
                    if let Ok(mut addrs) = addr.to_socket_addrs() {
                        if let Some(sock) = addrs.next() {
                            return TcpStream::connect_timeout(&sock, timeout).is_ok();
                        }
                    }
                    false
                }).await.unwrap_or(false);

                if is_open {
                    open_clone.lock().unwrap().push((port, get_service_name(port)));
                }
            });
            port_handles.push(handle);
        }

        for h in port_handles {
            let _ = h.await;
        }

        let mut found_ports = open_ports.lock().unwrap().clone();
        found_ports.sort_by_key(|(p, _)| *p);

        // Exibe resultado do host em tempo real
        if !found_ports.is_empty() {
            let port_list: Vec<String> = found_ports.iter()
                .map(|(p, s)| format!("{}/{}", p.to_string().bright_green(), s.bright_cyan()))
                .collect();
            println!("  {} {}  {}",
                "[UP]".bright_green().bold(),
                ip.bright_white().bold(),
                port_list.join("  ")
            );
        } else {
            println!("  {} {}  {}",
                "[UP]".bright_green(),
                ip.bright_white(),
                "sem portas abertas nas comuns".bright_black()
            );
        }

        results.lock().unwrap().push(HostResult {
            ip: ip.clone(),
            open_ports: found_ports,
        });

        pb_scan.inc(1);
    }

    pb_scan.finish_and_clear();

    // ── Sumário final ────────────────────────────────────────────────
    let all_results = results.lock().unwrap().clone();

    println!("\n{}", "─".repeat(65).bright_black());
    println!("{}", "  SUMÁRIO DO NETWORK SCAN".bright_white().bold());
    println!("{}", "─".repeat(65).bright_black());

    // Monta tabela com comfy_table
    use comfy_table::{Table, Cell, Color, Attribute};
    let mut table = Table::new();
    table.set_header(vec![
        Cell::new("Host").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Portas Abertas").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Serviços").add_attribute(Attribute::Bold).fg(Color::Cyan),
        Cell::new("Risco").add_attribute(Attribute::Bold).fg(Color::Cyan),
    ]);

    let hosts_com_portas: Vec<&HostResult> = all_results.iter()
        .filter(|r| !r.open_ports.is_empty())
        .collect();

    for r in &hosts_com_portas {
        let ports_str = r.open_ports.iter()
            .map(|(p, _)| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let services_str = r.open_ports.iter()
            .map(|(_, s)| *s)
            .collect::<Vec<_>>()
            .join(", ");

        let risk = risk_level(&r.open_ports);
        let risk_cell = match risk {
            "CRITICO" => Cell::new(risk).fg(Color::Red).add_attribute(Attribute::Bold),
            "ALTO"    => Cell::new(risk).fg(Color::Yellow).add_attribute(Attribute::Bold),
            "MEDIO"   => Cell::new(risk).fg(Color::Yellow),
            _         => Cell::new(risk).fg(Color::Green),
        };

        table.add_row(vec![
            Cell::new(&r.ip).fg(Color::White),
            Cell::new(&ports_str).fg(Color::Green),
            Cell::new(&services_str).fg(Color::Cyan),
            risk_cell,
        ]);
    }

    println!("{}", table);

    // Estatísticas
    let total_open: usize = all_results.iter().map(|r| r.open_ports.len()).sum();
    println!("\n  Rede         : {}", cidr.bright_yellow());
    println!("  Hosts vivos  : {}/{}", alive.len().to_string().bright_green().bold(), total_hosts);
    println!("  Com serviços : {}", hosts_com_portas.len().to_string().bright_yellow());
    println!("  Total de portas abertas: {}", total_open.to_string().bright_red().bold());

    // Alertas de serviços críticos
    let critical_ports = [21u16, 23, 445, 3389, 5900];
    let mut alerts: Vec<String> = Vec::new();
    for r in &all_results {
        for (port, service) in &r.open_ports {
            if critical_ports.contains(port) {
                alerts.push(format!("{} → porta {} ({}) exposta!", r.ip, port, service));
            }
        }
    }

    if !alerts.is_empty() {
        println!("\n  {} Serviços críticos expostos:", "[!]".bright_red().bold());
        for alert in &alerts {
            println!("    {} {}", "▸".bright_red(), alert.bright_yellow());
        }
    }

    // Export JSON
    if let Some(out_path) = output {
        export_netscan_json(&all_results, cidr, out_path)?;
        println!("\n{} Resultado exportado para {}", "[+]".bright_green().bold(), out_path.bright_yellow());
    }

    println!("{}", "─".repeat(65).bright_black());

    Ok(())
}

fn risk_level(ports: &[(u16, &'static str)]) -> &'static str {
    let critical = [21u16, 23, 445, 3389, 5900, 1433, 27017, 6379];
    let high     = [22u16, 3306, 5432, 110, 143, 1521];

    for (p, _) in ports {
        if critical.contains(p) { return "CRITICO"; }
    }
    for (p, _) in ports {
        if high.contains(p) { return "ALTO"; }
    }
    if ports.len() > 5 { return "MEDIO"; }
    if ports.is_empty() { return "BAIXO"; }
    "MEDIO"
}

fn export_netscan_json(results: &[HostResult], cidr: &str, path: &str) -> Result<()> {
    use std::io::Write;

    let json = serde_json::json!({
        "scan": cidr,
        "hosts": results.iter().map(|r| {
            serde_json::json!({
                "ip": r.ip,
                "open_ports": r.open_ports.iter().map(|(p, s)| {
                    serde_json::json!({ "port": p, "service": s })
                }).collect::<Vec<_>>(),
                "risk": risk_level(&r.open_ports),
            })
        }).collect::<Vec<_>>(),
    });

    let mut f = std::fs::File::create(path)?;
    f.write_all(serde_json::to_string_pretty(&json)?.as_bytes())?;
    Ok(())
}
