use anyhow::Result;
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};

use crate::cli::*;
use crate::modules;

// ─── Tema padrão ──────────────────────────────────────────────────────────

fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

// ─── Menu Principal ───────────────────────────────────────────────────────

pub async fn run_menu() -> Result<()> {
    let term = Term::stdout();

    loop {
        term.clear_screen()?;
        print_banner_compact();

        let opcoes = vec![
            "  Network Recon      — port scan, DNS, sweep, banner",
            "  Log Analyzer       — analisa logs, detecta ataques (SIEM)",
            "  Password Tools     — gera senhas, wordlist, verifica força",
            "  Hash Tools         — identifica, gera e crackeia hashes",
            "  Crypto Lab         — cifras, encodings, aprenda criptografia",
            "  Vuln Scanner       — FTP anon, SSH, HTTP headers, Redis, credenciais padrão",
            "  Sair",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha um módulo")
            .items(&opcoes)
            .default(0)
            .interact_on(&term)?;

        match escolha {
            0 => menu_network(&term).await?,
            1 => menu_logs(&term).await?,
            2 => menu_password(&term)?,
            3 => menu_hash(&term)?,
            4 => menu_crypto(&term)?,
            5 => menu_vuln(&term).await?,
            6 => {
                println!("\n{}", "  Até logo!".bright_cyan().bold());
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

// ─── Banner compacto ──────────────────────────────────────────────────────

fn print_banner_compact() {
    println!("{}", "  ╔══════════════════════════════════════════════════════════╗".bright_cyan());
    println!("{}", "  ║   SENTINELA — SOC Security Suite v0.1.0                 ║".bright_cyan());
    println!("{}", "  ║   Network │ Logs │ Password │ Hash │ Crypto              ║".bright_cyan());
    println!("{}", "  ╚══════════════════════════════════════════════════════════╝".bright_cyan());
    println!();
}

fn print_modulo(nome: &str) {
    println!();
    println!("  {} {}", "▶".bright_cyan().bold(), nome.bright_white().bold());
    println!("  {}", "─".repeat(55).bright_black());
    println!();
}

fn pausar() {
    let _ = Input::<String>::with_theme(&theme())
        .with_prompt("Pressione Enter para continuar")
        .allow_empty(true)
        .interact_text();
}

// ─── Menu Network ─────────────────────────────────────────────────────────

async fn menu_network(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("NETWORK RECON");

        let opcoes = vec![
            "  Network Scan /CIDR — scan completo: hosts vivos + portas (NOVO)",
            "  Port Scanner       — varre portas TCP de um host",
            "  DNS Lookup         — resolve registros DNS completos",
            "  Ping Sweep         — descobre hosts ativos em uma rede",
            "  Banner Grabbing    — lê o banner de um serviço",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("NETWORK SCAN — REDE COMPLETA /CIDR");

                println!("  {}", "Descobre hosts vivos e varre portas de cada um. Ideal para /24.".bright_black());
                println!();

                let cidr: String = Input::with_theme(&theme())
                    .with_prompt("Range CIDR (ex: 192.168.1.0/24)")
                    .interact_text()?;

                let portas_preset = vec![
                    "Comuns (22,80,443,3306,3389,445,21,23,8080,5432,5900)",
                    "Top 20 (mais usadas em pentest)",
                    "Personalizado",
                ];
                let preset_idx = Select::with_theme(&theme())
                    .with_prompt("Portas a varrer")
                    .items(&portas_preset)
                    .default(0)
                    .interact()?;

                let ports = match preset_idx {
                    0 => "21,22,23,25,53,80,110,135,139,143,443,445,554,1080,1900,3306,3389,5000,5432,5900,7070,8008,8009,8080,8443,8888,9000,9080,9090,62078".to_string(),
                    1 => "21,22,23,25,53,80,110,111,135,139,143,443,445,554,993,995,1080,1433,1521,1900,3306,3389,5000,5432,5900,6379,7070,8008,8009,8080,8443,8888,9000,9080,9090,27017,62078".to_string(),
                    _ => Input::with_theme(&theme())
                        .with_prompt("Portas (ex: 1-1024 ou 22,80,443)")
                        .interact_text()?,
                };

                let timeout: u64 = Input::with_theme(&theme())
                    .with_prompt("Timeout por porta (ms) — menor = mais rápido, mas perde portas lentas")
                    .default(400u64)
                    .interact_text()?;

                let threads: usize = Input::with_theme(&theme())
                    .with_prompt("Threads por host")
                    .default(100usize)
                    .interact_text()?;

                let exportar = Confirm::with_theme(&theme())
                    .with_prompt("Exportar resultado como JSON?")
                    .default(false)
                    .interact()?;

                let output = if exportar {
                    let path: String = Input::with_theme(&theme())
                        .with_prompt("Arquivo de saída")
                        .default("netscan.json".into())
                        .interact_text()?;
                    Some(path)
                } else {
                    None
                };

                println!();
                modules::network::run(NetworkArgs {
                    cmd: NetworkCmd::Netscan { cidr, ports, timeout, threads, output },
                }).await?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("PORT SCANNER");

                let target: String = Input::with_theme(&theme())
                    .with_prompt("Alvo (IP ou hostname)")
                    .interact_text()?;

                let ports: String = Input::with_theme(&theme())
                    .with_prompt("Portas (ex: 1-1024 ou 80,443,22,3389)")
                    .default("1-1024".into())
                    .interact_text()?;

                let timeout: u64 = Input::with_theme(&theme())
                    .with_prompt("Timeout por porta (ms)")
                    .default(500u64)
                    .interact_text()?;

                let threads: usize = Input::with_theme(&theme())
                    .with_prompt("Threads simultâneas")
                    .default(200usize)
                    .interact_text()?;

                println!();
                modules::network::run(NetworkArgs {
                    cmd: NetworkCmd::Scan { target, ports, timeout, threads },
                }).await?;
                pausar();
            }
            2 => {
                term.clear_screen()?;
                print_modulo("DNS LOOKUP");

                let target: String = Input::with_theme(&theme())
                    .with_prompt("Domínio (ex: example.com)")
                    .interact_text()?;

                println!();
                modules::network::run(NetworkArgs {
                    cmd: NetworkCmd::Dns { target, all: true },
                }).await?;
                pausar();
            }
            3 => {
                term.clear_screen()?;
                print_modulo("PING SWEEP");

                let cidr: String = Input::with_theme(&theme())
                    .with_prompt("Range CIDR (ex: 192.168.1.0/24)")
                    .interact_text()?;

                let timeout: u64 = Input::with_theme(&theme())
                    .with_prompt("Timeout (ms)")
                    .default(1000u64)
                    .interact_text()?;

                println!();
                modules::network::run(NetworkArgs {
                    cmd: NetworkCmd::Sweep { cidr, timeout },
                }).await?;
                pausar();
            }
            4 => {
                term.clear_screen()?;
                print_modulo("BANNER GRABBING");

                let target: String = Input::with_theme(&theme())
                    .with_prompt("Host (IP ou hostname)")
                    .interact_text()?;

                let port: u16 = Input::with_theme(&theme())
                    .with_prompt("Porta")
                    .default(22u16)
                    .interact_text()?;

                println!();
                modules::network::run(NetworkArgs {
                    cmd: NetworkCmd::Banner { target, port },
                }).await?;
                pausar();
            }
            5 => break,
            _ => {}
        }
    }
    Ok(())
}

// ─── Menu Logs ────────────────────────────────────────────────────────────

async fn menu_logs(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("LOG ANALYZER — SIEM");

        let opcoes = vec![
            "  Analisar arquivo   — detecta ataques e padrões suspeitos",
            "  Monitorar ao vivo  — tail -f com análise em tempo real",
            "  Buscar padrão      — busca regex em log com contexto",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("ANALISAR LOG");

                let file: String = Input::with_theme(&theme())
                    .with_prompt("Caminho do arquivo de log")
                    .default("/var/log/auth.log".into())
                    .interact_text()?;

                let formatos = vec!["auto-detect", "syslog", "auth", "nginx", "apache", "json"];
                let fmt_idx = Select::with_theme(&theme())
                    .with_prompt("Formato do log")
                    .items(&formatos)
                    .default(0)
                    .interact()?;
                let format = if fmt_idx == 0 { None } else { Some(formatos[fmt_idx].to_string()) };

                let stats = Confirm::with_theme(&theme())
                    .with_prompt("Mostrar estatísticas e top IPs?")
                    .default(true)
                    .interact()?;

                let exportar = Confirm::with_theme(&theme())
                    .with_prompt("Exportar alertas como JSON?")
                    .default(false)
                    .interact()?;

                let output = if exportar {
                    let path: String = Input::with_theme(&theme())
                        .with_prompt("Arquivo de saída")
                        .default("alertas.json".into())
                        .interact_text()?;
                    Some(path)
                } else {
                    None
                };

                println!();
                modules::logs::run(LogArgs {
                    cmd: LogCmd::Analyze { file, format, stats, output },
                }).await?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("MONITORAR LOG — TEMPO REAL");

                let file: String = Input::with_theme(&theme())
                    .with_prompt("Caminho do arquivo de log")
                    .default("/var/log/auth.log".into())
                    .interact_text()?;

                println!("\n  {} Pressione Ctrl+C para parar o monitoramento\n",
                    "[!]".bright_yellow());

                modules::logs::run(LogArgs {
                    cmd: LogCmd::Watch { file, format: None },
                }).await?;
            }
            2 => {
                term.clear_screen()?;
                print_modulo("BUSCAR EM LOG");

                let file: String = Input::with_theme(&theme())
                    .with_prompt("Caminho do arquivo de log")
                    .interact_text()?;

                let pattern: String = Input::with_theme(&theme())
                    .with_prompt("Padrão regex (ex: Failed password|192\\.168)")
                    .interact_text()?;

                let context: usize = Input::with_theme(&theme())
                    .with_prompt("Linhas de contexto antes/depois")
                    .default(0usize)
                    .interact_text()?;

                println!();
                modules::logs::run(LogArgs {
                    cmd: LogCmd::Search { file, pattern, context },
                }).await?;
                pausar();
            }
            3 => break,
            _ => {}
        }
    }
    Ok(())
}

// ─── Menu Password ────────────────────────────────────────────────────────

fn menu_password(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("PASSWORD TOOLS");

        let opcoes = vec![
            "  Gerar senhas      — senhas aleatórias seguras",
            "  Verificar força   — analisa senha + estimativa de crack",
            "  Gerar wordlist    — baseada em nome/empresa com mutações",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("GERAR SENHAS");

                let length: usize = Input::with_theme(&theme())
                    .with_prompt("Comprimento da senha")
                    .default(16usize)
                    .interact_text()?;

                let count: usize = Input::with_theme(&theme())
                    .with_prompt("Quantidade de senhas")
                    .default(5usize)
                    .interact_text()?;

                let upper = Confirm::with_theme(&theme())
                    .with_prompt("Incluir maiúsculas (A-Z)?")
                    .default(true).interact()?;

                let numbers = Confirm::with_theme(&theme())
                    .with_prompt("Incluir números (0-9)?")
                    .default(true).interact()?;

                let symbols = Confirm::with_theme(&theme())
                    .with_prompt("Incluir símbolos (!@#$...)?")
                    .default(true).interact()?;

                let no_ambiguous = Confirm::with_theme(&theme())
                    .with_prompt("Excluir ambíguos (0,O,l,I,1)?")
                    .default(false).interact()?;

                println!();
                modules::password::run(PasswordArgs {
                    cmd: PasswordCmd::Generate { length, count, upper, numbers, symbols, no_ambiguous },
                })?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("VERIFICAR FORÇA DE SENHA");

                let password: String = dialoguer::Password::with_theme(&theme())
                    .with_prompt("Digite a senha (oculta)")
                    .interact()?;

                let estimate = Confirm::with_theme(&theme())
                    .with_prompt("Estimar tempo de crack por GPU?")
                    .default(true).interact()?;

                println!();
                modules::password::run(PasswordArgs {
                    cmd: PasswordCmd::Check { password, estimate },
                })?;
                pausar();
            }
            2 => {
                term.clear_screen()?;
                print_modulo("GERAR WORDLIST");

                println!("  {}", "Gera variações de uma palavra base para testes de autenticação".bright_black());
                println!();

                let base: String = Input::with_theme(&theme())
                    .with_prompt("Palavra base (nome, empresa, etc)")
                    .interact_text()?;

                let leet = Confirm::with_theme(&theme())
                    .with_prompt("Aplicar leet speak (a→4, e→3, o→0)?")
                    .default(true).interact()?;

                let suffixes = Confirm::with_theme(&theme())
                    .with_prompt("Adicionar sufixos (123, 2024, !, @...)?")
                    .default(true).interact()?;

                let min_len: usize = Input::with_theme(&theme())
                    .with_prompt("Comprimento mínimo")
                    .default(6usize).interact_text()?;

                let max_len: usize = Input::with_theme(&theme())
                    .with_prompt("Comprimento máximo")
                    .default(20usize).interact_text()?;

                let salvar = Confirm::with_theme(&theme())
                    .with_prompt("Salvar em arquivo?")
                    .default(false).interact()?;

                let output = if salvar {
                    let path: String = Input::with_theme(&theme())
                        .with_prompt("Nome do arquivo")
                        .default(format!("{}_wordlist.txt", base))
                        .interact_text()?;
                    Some(path)
                } else {
                    None
                };

                println!();
                modules::password::run(PasswordArgs {
                    cmd: PasswordCmd::Wordlist { base, leet, suffixes, output, min_len, max_len },
                })?;
                pausar();
            }
            3 => break,
            _ => {}
        }
    }
    Ok(())
}

// ─── Menu Hash ────────────────────────────────────────────────────────────

fn menu_hash(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("HASH TOOLS");

        let opcoes = vec![
            "  Identificar hash   — descobre o algoritmo de um hash",
            "  Gerar hash         — gera hash de texto ou arquivo",
            "  Crackear hash      — ataque de dicionário com wordlist",
            "  Verificar arquivo  — checa integridade por hash",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("IDENTIFICAR HASH");

                let hash: String = Input::with_theme(&theme())
                    .with_prompt("Cole o hash aqui")
                    .interact_text()?;

                println!();
                modules::hash::run(HashArgs {
                    cmd: HashCmd::Identify { hash },
                })?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("GERAR HASH");

                let algos = vec!["sha256", "sha512", "sha1", "md5", "sha3-256"];
                let algo_idx = Select::with_theme(&theme())
                    .with_prompt("Algoritmo")
                    .items(&algos)
                    .default(0)
                    .interact()?;
                let algo = algos[algo_idx].to_string();

                let usar_arquivo = Confirm::with_theme(&theme())
                    .with_prompt("Hashear arquivo ao invés de texto?")
                    .default(false).interact()?;

                if usar_arquivo {
                    let file: String = Input::with_theme(&theme())
                        .with_prompt("Caminho do arquivo")
                        .interact_text()?;
                    println!();
                    modules::hash::run(HashArgs {
                        cmd: HashCmd::Generate { input: String::new(), algo, file: Some(file) },
                    })?;
                } else {
                    let input: String = Input::with_theme(&theme())
                        .with_prompt("Texto para hashear")
                        .interact_text()?;
                    println!();
                    modules::hash::run(HashArgs {
                        cmd: HashCmd::Generate { input, algo, file: None },
                    })?;
                }
                pausar();
            }
            2 => {
                term.clear_screen()?;
                print_modulo("CRACKEAR HASH");

                println!("  {}", "Tenta encontrar o plaintext de um hash via wordlist".bright_black());
                println!();

                let hash: String = Input::with_theme(&theme())
                    .with_prompt("Hash alvo")
                    .interact_text()?;

                let wordlists_comuns = vec![
                    "/usr/share/wordlists/rockyou.txt",
                    "/usr/share/wordlists/fasttrack.txt",
                    "Outro caminho...",
                ];

                let wl_idx = Select::with_theme(&theme())
                    .with_prompt("Wordlist")
                    .items(&wordlists_comuns)
                    .default(0)
                    .interact()?;

                let wordlist = if wl_idx == wordlists_comuns.len() - 1 {
                    Input::with_theme(&theme())
                        .with_prompt("Caminho da wordlist")
                        .interact_text()?
                } else {
                    wordlists_comuns[wl_idx].to_string()
                };

                let threads: usize = Input::with_theme(&theme())
                    .with_prompt("Threads paralelas")
                    .default(4usize).interact_text()?;

                println!();
                modules::hash::run(HashArgs {
                    cmd: HashCmd::Crack { hash, algo: None, wordlist, threads },
                })?;
                pausar();
            }
            3 => {
                term.clear_screen()?;
                print_modulo("VERIFICAR INTEGRIDADE");

                let file: String = Input::with_theme(&theme())
                    .with_prompt("Caminho do arquivo")
                    .interact_text()?;

                let hash: String = Input::with_theme(&theme())
                    .with_prompt("Hash esperado")
                    .interact_text()?;

                let algos = vec!["sha256", "sha512", "sha1", "md5"];
                let algo_idx = Select::with_theme(&theme())
                    .with_prompt("Algoritmo")
                    .items(&algos)
                    .default(0).interact()?;

                println!();
                modules::hash::run(HashArgs {
                    cmd: HashCmd::Verify {
                        file,
                        hash,
                        algo: algos[algo_idx].to_string(),
                    },
                })?;
                pausar();
            }
            4 => break,
            _ => {}
        }
    }
    Ok(())
}

// ─── Menu Crypto ──────────────────────────────────────────────────────────

fn menu_crypto(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("CRYPTO LAB");

        let opcoes = vec![
            "  Codificar/Decodificar — Base64, Hex, URL, ROT13, Binary",
            "  Cifrar/Decifrar       — César, Vigenère, XOR, Atbash",
            "  Análise de frequência — quebra cifras clássicas",
            "  Aprender criptografia — tutoriais interativos",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("CODIFICAR / DECODIFICAR");

                let esquemas = vec!["base64", "hex", "url", "rot13", "binary", "reverse"];
                let idx = Select::with_theme(&theme())
                    .with_prompt("Esquema")
                    .items(&esquemas)
                    .default(0).interact()?;
                let scheme = esquemas[idx].to_string();

                let decode = Confirm::with_theme(&theme())
                    .with_prompt("Decodificar (ao invés de codificar)?")
                    .default(false).interact()?;

                let input: String = Input::with_theme(&theme())
                    .with_prompt(if decode { "Texto codificado" } else { "Texto a codificar" })
                    .interact_text()?;

                println!();
                modules::crypto::run(CryptoArgs {
                    cmd: CryptoCmd::Encode { input, scheme, decode },
                })?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("CIFRAR / DECIFRAR");

                let cifras = vec!["caesar", "vigenere", "xor", "atbash"];
                let descricoes = vec![
                    "Caesar   — shift de N posições no alfabeto",
                    "Vigenère — chave polialfabética",
                    "XOR      — operação bit a bit (chave 0-255)",
                    "Atbash   — espelho do alfabeto (A↔Z)",
                ];

                let idx = Select::with_theme(&theme())
                    .with_prompt("Cifra")
                    .items(&descricoes)
                    .default(0).interact()?;
                let cipher = cifras[idx].to_string();

                let key: String = match cipher.as_str() {
                    "caesar" => Input::with_theme(&theme())
                        .with_prompt("Shift (0-25)")
                        .default("13".into())
                        .interact_text()?,
                    "vigenere" => Input::with_theme(&theme())
                        .with_prompt("Chave (palavra, ex: SECRET)")
                        .interact_text()?,
                    "xor" => Input::with_theme(&theme())
                        .with_prompt("Chave XOR (0-255)")
                        .default("42".into())
                        .interact_text()?,
                    _ => "0".to_string(),
                };

                let decrypt = Confirm::with_theme(&theme())
                    .with_prompt("Decifrar (ao invés de cifrar)?")
                    .default(false).interact()?;

                let input: String = Input::with_theme(&theme())
                    .with_prompt(if decrypt { "Texto cifrado" } else { "Texto original" })
                    .interact_text()?;

                println!();
                modules::crypto::run(CryptoArgs {
                    cmd: CryptoCmd::Cipher { input, cipher, key, decrypt },
                })?;
                pausar();
            }
            2 => {
                term.clear_screen()?;
                print_modulo("ANÁLISE DE FREQUÊNCIA");

                println!("  {}", "Cole um texto cifrado para descobrir padrões de letras.".bright_black());
                println!("  {}", "Útil para quebrar cifras de César e Vigenère.".bright_black());
                println!();

                let text: String = Input::with_theme(&theme())
                    .with_prompt("Texto cifrado")
                    .interact_text()?;

                println!();
                modules::crypto::run(CryptoArgs {
                    cmd: CryptoCmd::Frequency { text },
                })?;
                pausar();
            }
            3 => {
                term.clear_screen()?;
                print_modulo("APRENDER CRIPTOGRAFIA");

                let topicos = vec![
                    "caesar   — Cifra de César (deslocamento)",
                    "vigenere — Cifra de Vigenère (polialfabética)",
                    "xor      — XOR Cipher (base de tudo)",
                    "base64   — Base64 (não é criptografia!)",
                    "hashing  — MD5, SHA, bcrypt — como funcionam",
                    "aes      — AES (padrão mundial atual)",
                    "Menu geral (todos os tópicos)",
                ];
                let nomes = vec![
                    Some("caesar"), Some("vigenere"), Some("xor"),
                    Some("base64"), Some("hashing"), Some("aes"), None,
                ];

                let idx = Select::with_theme(&theme())
                    .with_prompt("Qual tópico quer aprender?")
                    .items(&topicos)
                    .default(0).interact()?;

                println!();
                modules::crypto::run(CryptoArgs {
                    cmd: CryptoCmd::Learn { topic: nomes[idx].map(|s| s.to_string()) },
                })?;
                pausar();
            }
            4 => break,
            _ => {}
        }
    }
    Ok(())
}

// ─── Menu Vuln ────────────────────────────────────────────────────────────

async fn menu_vuln(term: &Term) -> Result<()> {
    loop {
        term.clear_screen()?;
        print_banner_compact();
        print_modulo("VULNERABILITY SCANNER");

        println!("  {}", "Checks: FTP anon, Telnet, SSH versão, HTTP headers, TRACE,".bright_black());
        println!("  {}", "        Redis/MongoDB sem auth, MySQL versão, VNC, SMB, credenciais padrão".bright_black());
        println!();

        let opcoes = vec![
            "  Scan de host       — verifica um alvo específico",
            "  Scan de rede /CIDR — varre toda a rede em busca de vulns",
            "  Voltar",
        ];

        let escolha = Select::with_theme(&theme())
            .with_prompt("Escolha uma ação")
            .items(&opcoes)
            .default(0)
            .interact_on(term)?;

        match escolha {
            0 => {
                term.clear_screen()?;
                print_modulo("VULN SCAN — HOST");

                let target: String = Input::with_theme(&theme())
                    .with_prompt("Host alvo (IP ou hostname)")
                    .interact_text()?;

                let ports: String = Input::with_theme(&theme())
                    .with_prompt("Portas a verificar")
                    .default("21,22,23,25,80,443,445,3306,5900,6379,8080,8443,9000,27017".into())
                    .interact_text()?;

                let timeout: u64 = Input::with_theme(&theme())
                    .with_prompt("Timeout de conexão (ms)")
                    .default(3000u64)
                    .interact_text()?;

                let exportar = Confirm::with_theme(&theme())
                    .with_prompt("Exportar relatório como JSON?")
                    .default(false)
                    .interact()?;

                let output = if exportar {
                    let path: String = Input::with_theme(&theme())
                        .with_prompt("Arquivo de saída")
                        .default(format!("vuln_{}.json", target.replace('.', "_")))
                        .interact_text()?;
                    Some(path)
                } else {
                    None
                };

                println!();
                modules::vuln::run(VulnArgs {
                    cmd: VulnCmd::Scan { target, ports, timeout, output },
                }).await?;
                pausar();
            }
            1 => {
                term.clear_screen()?;
                print_modulo("VULN SCAN — REDE COMPLETA");

                println!("  {}", "Descobre hosts vivos e verifica vulnerabilidades em cada um.".bright_black());
                println!();

                let cidr: String = Input::with_theme(&theme())
                    .with_prompt("Range CIDR (ex: 192.168.0.0/24)")
                    .interact_text()?;

                let timeout: u64 = Input::with_theme(&theme())
                    .with_prompt("Timeout de conexão (ms)")
                    .default(2000u64)
                    .interact_text()?;

                let exportar = Confirm::with_theme(&theme())
                    .with_prompt("Exportar relatório como JSON?")
                    .default(true)
                    .interact()?;

                let output = if exportar {
                    let path: String = Input::with_theme(&theme())
                        .with_prompt("Arquivo de saída")
                        .default("vuln_network.json".into())
                        .interact_text()?;
                    Some(path)
                } else {
                    None
                };

                println!();
                modules::vuln::run(VulnArgs {
                    cmd: VulnCmd::Netscan { cidr, timeout, output },
                }).await?;
                pausar();
            }
            2 => break,
            _ => {}
        }
    }
    Ok(())
}
