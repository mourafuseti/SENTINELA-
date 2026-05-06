use anyhow::Result;
use colored::*;
use regex::Regex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

use crate::cli::{LogArgs, LogCmd};

pub async fn run(args: LogArgs) -> Result<()> {
    match args.cmd {
        LogCmd::Analyze { file, format, stats, output } => {
            analyze_log(&file, format.as_deref(), stats, output.as_deref())?;
        }
        LogCmd::Watch { file, format } => {
            watch_log(&file, format.as_deref())?;
        }
        LogCmd::Search { file, pattern, context } => {
            search_log(&file, &pattern, context)?;
        }
    }
    Ok(())
}

// ─── Tipos de Alerta ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct Alert {
    severity: Severity,
    rule: String,
    line_no: usize,
    line: String,
    details: String,
}

#[derive(Debug, Clone, PartialEq)]
enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
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
    fn score(&self) -> u32 {
        match self {
            Severity::Critical => 5,
            Severity::High => 4,
            Severity::Medium => 3,
            Severity::Low => 2,
            Severity::Info => 1,
        }
    }
}

// ─── Regras SIEM ──────────────────────────────────────────────────────────

struct Rule {
    name: &'static str,
    pattern: Regex,
    severity: Severity,
    description: &'static str,
}

fn build_rules() -> Vec<Rule> {
    vec![
        Rule {
            name: "Brute Force SSH",
            pattern: Regex::new(r"Failed password for .+ from \d+\.\d+\.\d+\.\d+").unwrap(),
            severity: Severity::High,
            description: "Tentativa de autenticação SSH falha detectada",
        },
        Rule {
            name: "Root Login",
            pattern: Regex::new(r"(Accepted|Failed) password for root").unwrap(),
            severity: Severity::Critical,
            description: "Tentativa de login como root",
        },
        Rule {
            name: "Invalid User",
            pattern: Regex::new(r"Invalid user \w+ from \d+\.\d+\.\d+\.\d+").unwrap(),
            severity: Severity::Medium,
            description: "Tentativa de login com usuário inexistente",
        },
        Rule {
            name: "SQL Injection",
            pattern: Regex::new(r"(?i)(union\s+select|or\s+1=1|drop\s+table|insert\s+into|exec\s*\(|xp_cmdshell|information_schema)").unwrap(),
            severity: Severity::Critical,
            description: "Padrão de SQL Injection detectado",
        },
        Rule {
            name: "XSS Attempt",
            pattern: Regex::new(r"(?i)(<script|javascript:|onerror=|onload=|alert\s*\(|document\.cookie)").unwrap(),
            severity: Severity::High,
            description: "Tentativa de Cross-Site Scripting (XSS)",
        },
        Rule {
            name: "Path Traversal",
            pattern: Regex::new(r"(\.\./){2,}|%2e%2e%2f|%252e%252e%252f").unwrap(),
            severity: Severity::High,
            description: "Tentativa de Path Traversal / Directory Traversal",
        },
        Rule {
            name: "Scanner Web",
            pattern: Regex::new(r"(?i)(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|nuclei|burpsuite)").unwrap(),
            severity: Severity::Medium,
            description: "User-agent de ferramenta de scanning detectado",
        },
        Rule {
            name: "Shell Upload",
            pattern: Regex::new(r"(?i)(cmd\.php|shell\.php|webshell|c99\.php|r57\.php|eval\(base64_decode)").unwrap(),
            severity: Severity::Critical,
            description: "Possível upload de web shell",
        },
        Rule {
            name: "Sudo Elevation",
            pattern: Regex::new(r"sudo:.+(COMMAND|command)=").unwrap(),
            severity: Severity::Low,
            description: "Execução via sudo registrada",
        },
        Rule {
            name: "Privilege Escalation",
            pattern: Regex::new(r"sudo:.+NOT in sudoers|sudo:.+authentication failure").unwrap(),
            severity: Severity::High,
            description: "Tentativa de escalada de privilégio",
        },
        Rule {
            name: "Port Scan Detect",
            pattern: Regex::new(r"SRC=\d+\.\d+\.\d+\.\d+.+DPT=(22|23|80|443|3389|445|139)\s").unwrap(),
            severity: Severity::Medium,
            description: "Possível varredura de portas no firewall",
        },
        Rule {
            name: "HTTP 500 Errors",
            pattern: Regex::new(r#""(GET|POST|PUT|DELETE) .+" 5\d\d "#).unwrap(),
            severity: Severity::Low,
            description: "Erros HTTP 5xx (falhas internas do servidor)",
        },
        Rule {
            name: "Large Response",
            pattern: Regex::new(r#""(GET|POST) .+" 200 [0-9]{7,}"#).unwrap(),
            severity: Severity::Low,
            description: "Resposta muito grande — possível exfiltração",
        },
        Rule {
            name: "Cron Job Added",
            pattern: Regex::new(r"(crontab|CRON|cron).+(new job|REPLACE|BEGIN EDIT)").unwrap(),
            severity: Severity::Medium,
            description: "Modificação em cron job detectada",
        },
        Rule {
            name: "Passwd File Modified",
            pattern: Regex::new(r"(useradd|usermod|passwd|shadow|/etc/passwd|/etc/shadow)").unwrap(),
            severity: Severity::High,
            description: "Possível modificação em arquivo de autenticação",
        },
    ]
}

// ─── Analisador Principal ─────────────────────────────────────────────────

fn auto_detect_format(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    if lower.contains("auth") || lower.contains("secure") { "auth" }
    else if lower.contains("nginx") { "nginx" }
    else if lower.contains("apache") || lower.contains("access") { "apache" }
    else if lower.ends_with(".json") { "json" }
    else { "syslog" }
}

fn analyze_log(path: &str, format: Option<&str>, show_stats: bool, output: Option<&str>) -> Result<()> {
    let format = format.unwrap_or_else(|| auto_detect_format(path));

    println!("{} {} {}  {}",
        "[*]".bright_blue().bold(),
        "Analisando:".bright_white(),
        path.bright_yellow(),
        format!("(formato: {})", format).bright_black()
    );
    println!("{}", "─".repeat(70).bright_black());

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let rules = build_rules();

    let mut alerts: Vec<Alert> = Vec::new();
    let mut total_lines = 0usize;
    let mut ip_counts: HashMap<String, usize> = HashMap::new();

    let ip_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;

    for (line_no, line_result) in reader.lines().enumerate() {
        let line = line_result?;
        total_lines += 1;

        // Conta IPs para estatísticas
        for cap in ip_re.captures_iter(&line) {
            let ip = cap[1].to_string();
            *ip_counts.entry(ip).or_insert(0) += 1;
        }

        // Aplica regras
        for rule in &rules {
            if rule.pattern.is_match(&line) {
                alerts.push(Alert {
                    severity: rule.severity.clone(),
                    rule: rule.name.to_string(),
                    line_no: line_no + 1,
                    line: line.clone(),
                    details: rule.description.to_string(),
                });
            }
        }
    }

    // Ordena por severidade
    alerts.sort_by_key(|a| std::cmp::Reverse(a.severity.score()));

    // Exibe alertas
    if alerts.is_empty() {
        println!("{} Nenhum alerta detectado", "[+]".bright_green().bold());
    } else {
        for alert in &alerts {
            println!("{} {} {} {}",
                alert.severity.label(),
                format!("L{:<6}", alert.line_no).bright_black(),
                alert.rule.bright_white().bold(),
                format!("— {}", alert.details).bright_black()
            );
            let preview: String = alert.line.chars().take(100).collect();
            println!("         {}", preview.bright_black().italic());
        }
    }

    println!("{}", "─".repeat(70).bright_black());

    // Estatísticas
    if show_stats || alerts.len() > 0 {
        println!("\n{}", "RESUMO ESTATÍSTICO".bright_white().bold());
        println!("  Total de linhas : {}", total_lines.to_string().bright_yellow());
        println!("  Total de alertas: {}", alerts.len().to_string().bright_red().bold());

        let mut by_severity: HashMap<String, usize> = HashMap::new();
        for a in &alerts {
            *by_severity.entry(format!("{:?}", a.severity)).or_insert(0) += 1;
        }
        for (sev, count) in &by_severity {
            println!("    {:10} : {}", sev, count.to_string().bright_yellow());
        }

        if show_stats && !ip_counts.is_empty() {
            println!("\n{}", "TOP 10 IPs mais ativos:".bright_white().bold());
            let mut ip_vec: Vec<(&String, &usize)> = ip_counts.iter().collect();
            ip_vec.sort_by(|a, b| b.1.cmp(a.1));
            for (ip, count) in ip_vec.iter().take(10) {
                println!("  {:20} {} requests", ip.bright_yellow(), count.to_string().bright_white());
            }
        }
    }

    // Exporta JSON se solicitado
    if let Some(out_path) = output {
        export_alerts_json(&alerts, out_path)?;
        println!("\n{} Alertas exportados para {}", "[+]".bright_green().bold(), out_path.bright_yellow());
    }

    Ok(())
}

fn export_alerts_json(alerts: &[Alert], path: &str) -> Result<()> {
    use std::io::Write;

    let json_alerts: Vec<serde_json::Value> = alerts.iter().map(|a| {
        serde_json::json!({
            "severity": format!("{:?}", a.severity),
            "rule": a.rule,
            "line": a.line_no,
            "details": a.details,
            "content": a.line,
        })
    }).collect();

    let json = serde_json::to_string_pretty(&json_alerts)?;
    let mut f = File::create(path)?;
    f.write_all(json.as_bytes())?;
    Ok(())
}

// ─── Watch (tail -f com análise) ──────────────────────────────────────────

fn watch_log(path: &str, format: Option<&str>) -> Result<()> {
    use std::thread;
    use std::time::Duration;
    use std::io::Seek;

    let format = format.unwrap_or_else(|| auto_detect_format(path));
    let rules = build_rules();

    println!("{} {} {} {}",
        "[*]".bright_blue().bold(),
        "Monitorando:".bright_white(),
        path.bright_yellow(),
        "(Ctrl+C para parar)".bright_black()
    );
    println!("{}", "─".repeat(70).bright_black());

    let mut file = File::open(path)?;
    file.seek(std::io::SeekFrom::End(0))?;
    let mut reader = BufReader::new(file);
    let mut line_no = 0usize;

    loop {
        let mut line = String::new();
        match reader.read_line(&mut line) {
            Ok(0) => {
                thread::sleep(Duration::from_millis(200));
            }
            Ok(_) => {
                line_no += 1;
                let line = line.trim_end().to_string();

                let mut matched = false;
                for rule in &rules {
                    if rule.pattern.is_match(&line) {
                        let preview: String = line.chars().take(90).collect();
                        println!("{} {} {} — {}",
                            rule.severity.label(),
                            format!("L{}", line_no).bright_black(),
                            rule.name.bright_white().bold(),
                            preview.bright_black()
                        );
                        matched = true;
                    }
                }

                if !matched {
                    // Mostra linha normal com dim
                    let preview: String = line.chars().take(100).collect();
                    println!("{} {}", format!("L{:<5}", line_no).bright_black(), preview.dimmed());
                }

                let _ = format; // suppress unused warning
            }
            Err(e) => {
                eprintln!("{} Erro de leitura: {}", "[-]".bright_red(), e);
                break;
            }
        }
    }

    Ok(())
}

// ─── Search ───────────────────────────────────────────────────────────────

fn search_log(path: &str, pattern: &str, context_lines: usize) -> Result<()> {
    let re = Regex::new(pattern)?;

    println!("{} Buscando '{}' em {}",
        "[*]".bright_blue().bold(),
        pattern.bright_yellow(),
        path.bright_white()
    );
    println!("{}", "─".repeat(70).bright_black());

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let lines: Vec<String> = reader.lines().filter_map(|l| l.ok()).collect();

    let mut matches = 0;
    for (i, line) in lines.iter().enumerate() {
        if re.is_match(line) {
            matches += 1;

            // Contexto antes
            if context_lines > 0 {
                let start = i.saturating_sub(context_lines);
                for ctx_i in start..i {
                    println!("  {} {}", format!("{:<6}:", ctx_i + 1).bright_black(), lines[ctx_i].dimmed());
                }
            }

            // Linha com match (highlight)
            let highlighted = re.replace_all(line, |caps: &regex::Captures| {
                caps[0].bright_yellow().bold().to_string()
            });
            println!("  {} {}", format!("{:<6}:", i + 1).bright_green().bold(), highlighted);

            // Contexto depois
            if context_lines > 0 {
                let end = (i + context_lines + 1).min(lines.len());
                for ctx_i in (i + 1)..end {
                    println!("  {} {}", format!("{:<6}:", ctx_i + 1).bright_black(), lines[ctx_i].dimmed());
                }
                println!("{}", "--".bright_black());
            }
        }
    }

    println!("{}", "─".repeat(70).bright_black());
    println!("{} {} correspondências encontradas", "[+]".bright_green().bold(), matches.to_string().bright_yellow());

    Ok(())
}

use std::cmp::Reverse;
