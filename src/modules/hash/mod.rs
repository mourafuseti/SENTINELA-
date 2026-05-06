use anyhow::Result;
use colored::*;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use rayon::prelude::*;

use sha2::{Sha256, Sha512, Digest as Sha2Digest};
use sha1::Sha1;
use sha3::{Sha3_256};
use md5::Md5;

use crate::cli::{HashArgs, HashCmd};

pub fn run(args: HashArgs) -> Result<()> {
    match args.cmd {
        HashCmd::Identify { hash } => {
            identify_hash(&hash)?;
        }
        HashCmd::Generate { input, algo, file } => {
            generate_hash(&input, &algo, file.as_deref())?;
        }
        HashCmd::Crack { hash, algo, wordlist, threads } => {
            crack_hash(&hash, algo.as_deref(), &wordlist, threads)?;
        }
        HashCmd::Verify { file, hash, algo } => {
            verify_file(&file, &hash, &algo)?;
        }
    }
    Ok(())
}

// ─── Identificador de Hash ────────────────────────────────────────────────

#[derive(Debug)]
struct HashInfo {
    name: &'static str,
    length: usize,
    description: &'static str,
    crackable: bool,
}

fn known_hashes() -> Vec<HashInfo> {
    vec![
        HashInfo { name: "MD5",        length: 32,  description: "Message Digest 5 — obsoleto, não use para senhas", crackable: true },
        HashInfo { name: "SHA-1",      length: 40,  description: "Secure Hash Algorithm 1 — depreciado", crackable: true },
        HashInfo { name: "SHA-256",    length: 64,  description: "SHA-2 256 bits — amplamente usado, seguro", crackable: false },
        HashInfo { name: "SHA-512",    length: 128, description: "SHA-2 512 bits — mais seguro que SHA-256", crackable: false },
        HashInfo { name: "SHA3-256",   length: 64,  description: "SHA-3 256 bits — família Keccak", crackable: false },
        HashInfo { name: "SHA3-512",   length: 128, description: "SHA-3 512 bits — família Keccak", crackable: false },
        HashInfo { name: "RIPEMD-160", length: 40,  description: "RIPEMD 160 bits — usado em Bitcoin", crackable: false },
        HashInfo { name: "bcrypt",     length: 60,  description: "Bcrypt — algoritmo lento para senhas, seguro", crackable: false },
        HashInfo { name: "CRC32",      length: 8,   description: "Cyclic Redundancy Check — checksum, não criptográfico", crackable: true },
        HashInfo { name: "MySQL323",   length: 16,  description: "Hash MySQL antigo (< 4.1) — muito fraco", crackable: true },
        HashInfo { name: "NTLM",       length: 32,  description: "Hash NTLM Windows — crackável com GPU", crackable: true },
        HashInfo { name: "LM",         length: 32,  description: "LAN Manager — obsoleto e extremamente fraco", crackable: true },
    ]
}

fn identify_hash(hash: &str) -> Result<()> {
    let hash = hash.trim();
    let len = hash.len();
    let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());
    let is_bcrypt = hash.starts_with("$2") && hash.len() == 60;

    println!("{} {} '{}'",
        "[*]".bright_blue().bold(),
        "Identificando hash:".bright_white(),
        hash.bright_yellow()
    );
    println!("{}", "─".repeat(65).bright_black());
    println!("  Comprimento : {} chars", len.to_string().bright_yellow());
    println!("  Caracteres  : {}", if is_hex { "hexadecimal".bright_green() } else { "misto/base64".bright_yellow() });
    println!();

    let candidates: Vec<&HashInfo> = known_hashes().iter()
        .filter(|h| {
            if is_bcrypt && h.name == "bcrypt" { return true; }
            is_hex && h.length == len
        })
        .collect();

    // Não pode usar .iter() on Vec<&HashInfo> diretamente sem escopo
    // Rebuild without lifetime issues
    let all_hashes = known_hashes();
    let candidates: Vec<&HashInfo> = all_hashes.iter()
        .filter(|h| {
            if is_bcrypt && h.name == "bcrypt" { return true; }
            is_hex && h.length == len
        })
        .collect();

    if candidates.is_empty() {
        println!("  {}", "Nenhum tipo de hash reconhecido para este formato".bright_red());
        println!("  Comprimento {} não corresponde a algoritmos comuns", len);
    } else {
        println!("  {} Tipos prováveis:", "▸".bright_cyan().bold());
        for h in &candidates {
            let crack_tag = if h.crackable {
                " [CRACKÁVEL]".bright_red().bold()
            } else {
                " [resistente]".bright_green()
            };
            println!("    {} {}{}",
                "●".bright_cyan(),
                h.name.bright_white().bold(),
                crack_tag
            );
            println!("      {}", h.description.bright_black());
        }

        if candidates.iter().any(|h| h.crackable) {
            println!("\n  {} Este hash pode ser crackado com: {} crack -H {} -w rockyou.txt",
                "Dica:".bright_yellow().bold(),
                "sentinela hash".bright_cyan(),
                hash.bright_white()
            );
        }
    }

    println!("{}", "─".repeat(65).bright_black());

    Ok(())
}

// ─── Gerador de Hash ──────────────────────────────────────────────────────

fn hash_string(input: &str, algo: &str) -> Result<String> {
    let algo_lower = algo.to_lowercase();
    let bytes = input.as_bytes();

    let result = match algo_lower.as_str() {
        "md5" => {
            let mut h = Md5::new();
            h.update(bytes);
            hex::encode(h.finalize())
        }
        "sha1" => {
            let mut h = Sha1::new();
            h.update(bytes);
            hex::encode(h.finalize())
        }
        "sha256" | "sha2-256" => {
            let mut h = Sha256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        }
        "sha512" | "sha2-512" => {
            let mut h = Sha512::new();
            h.update(bytes);
            hex::encode(h.finalize())
        }
        "sha3-256" | "sha3_256" => {
            let mut h = Sha3_256::new();
            h.update(bytes);
            hex::encode(h.finalize())
        }
        _ => anyhow::bail!("Algoritmo desconhecido: {}. Use: md5, sha1, sha256, sha512, sha3-256", algo),
    };

    Ok(result)
}

fn hash_bytes(data: &[u8], algo: &str) -> Result<String> {
    let algo_lower = algo.to_lowercase();
    let result = match algo_lower.as_str() {
        "md5" => {
            let mut h = Md5::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        "sha1" => {
            let mut h = Sha1::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        "sha256" | "sha2-256" => {
            let mut h = Sha256::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        "sha512" | "sha2-512" => {
            let mut h = Sha512::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        "sha3-256" | "sha3_256" => {
            let mut h = Sha3_256::new();
            h.update(data);
            hex::encode(h.finalize())
        }
        _ => anyhow::bail!("Algoritmo desconhecido: {}", algo),
    };
    Ok(result)
}

fn generate_hash(input: &str, algo: &str, file: Option<&str>) -> Result<()> {
    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Gerando hash".bright_white(),
        format!("({})", algo.to_uppercase()).bright_yellow()
    );
    println!("{}", "─".repeat(65).bright_black());

    if let Some(file_path) = file {
        let mut data = Vec::new();
        File::open(file_path)?.read_to_end(&mut data)?;
        let hash_val = hash_bytes(&data, algo)?;
        println!("  {} {}", "Arquivo :".bright_black(), file_path.bright_white());
        println!("  {} {}", "Tamanho :".bright_black(), format!("{} bytes", data.len()).bright_yellow());
        println!("  {} {}", format!("{:<8}:", algo.to_uppercase()).bright_black(), hash_val.bright_green().bold());
    } else {
        let hash_val = hash_string(input, algo)?;

        // Gera todos os algoritmos para comparação
        let algos = [("MD5", "md5"), ("SHA-1", "sha1"), ("SHA-256", "sha256"), ("SHA-512", "sha512"), ("SHA3-256", "sha3-256")];

        println!("  {} {}", "Input:".bright_black(), input.bright_white());
        println!();
        for (name, a) in &algos {
            if let Ok(h) = hash_string(input, a) {
                let line = if a.to_lowercase() == algo.to_lowercase() {
                    format!("  {:<12} {}", format!("{}:", name), h).bright_green().bold().to_string()
                } else {
                    format!("  {:<12} {}", format!("{}:", name), h).bright_black().to_string()
                };
                println!("{}", line);
            }
        }
    }

    println!("{}", "─".repeat(65).bright_black());

    Ok(())
}

// ─── Crack de Hash ────────────────────────────────────────────────────────

fn detect_algo(hash: &str) -> Option<&'static str> {
    let len = hash.len();
    let is_hex = hash.chars().all(|c| c.is_ascii_hexdigit());
    if !is_hex { return None; }
    match len {
        32  => Some("md5"),
        40  => Some("sha1"),
        64  => Some("sha256"),
        128 => Some("sha512"),
        _   => None,
    }
}

fn crack_hash(hash: &str, algo: Option<&str>, wordlist_path: &str, _threads: usize) -> Result<()> {
    let hash = hash.trim().to_lowercase();

    let algo = match algo {
        Some(a) => a.to_string(),
        None => {
            match detect_algo(&hash) {
                Some(a) => {
                    println!("{} Algoritmo detectado automaticamente: {}", "[*]".bright_blue(), a.to_uppercase().bright_yellow());
                    a.to_string()
                }
                None => anyhow::bail!("Não foi possível detectar o algoritmo. Use --algo para especificar."),
            }
        }
    };

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Crackando hash:".bright_white(),
        hash.bright_yellow()
    );
    println!("  Algoritmo: {} | Wordlist: {}",
        algo.to_uppercase().bright_cyan(),
        wordlist_path.bright_white()
    );
    println!("{}", "─".repeat(65).bright_black());

    let file = File::open(wordlist_path)
        .map_err(|_| anyhow::anyhow!("Wordlist não encontrada: {}", wordlist_path))?;
    let reader = BufReader::new(file);

    let words: Vec<String> = reader.lines()
        .filter_map(|l| l.ok())
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();

    let total = words.len();
    println!("  {} palavras carregadas\n", total.to_string().bright_yellow());

    use indicatif::{ProgressBar, ProgressStyle};
    let pb = ProgressBar::new(total as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("  [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
        .unwrap()
        .progress_chars("=>-"));

    // Busca paralela com rayon
    let found: Option<String> = words.par_iter()
        .find_map_any(|word| {
            pb.inc(1);
            if let Ok(h) = hash_string(word, &algo) {
                if h == hash {
                    return Some(word.clone());
                }
            }
            None
        });

    pb.finish_and_clear();

    println!("{}", "─".repeat(65).bright_black());

    match found {
        Some(plaintext) => {
            println!("{} HASH CRACKADO!",  "[+]".bright_green().bold());
            println!("  Hash      : {}", hash.bright_yellow());
            println!("  Plaintext : {}", plaintext.bright_green().bold());
            println!("\n  {} Troque esta senha imediatamente!", "AVISO:".bright_red().bold());
        }
        None => {
            println!("{} Não encontrado na wordlist ({} palavras testadas)",
                "[-]".bright_yellow().bold(),
                total.to_string().bright_yellow()
            );
            println!("  Tente uma wordlist maior (ex: rockyou.txt, SecLists)");
        }
    }

    Ok(())
}

// ─── Verificação de Integridade ───────────────────────────────────────────

fn verify_file(file_path: &str, expected_hash: &str, algo: &str) -> Result<()> {
    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Verificando integridade:".bright_white(),
        file_path.bright_yellow()
    );
    println!("{}", "─".repeat(65).bright_black());

    let mut data = Vec::new();
    File::open(file_path)?.read_to_end(&mut data)?;

    let computed = hash_bytes(&data, algo)?;
    let expected = expected_hash.trim().to_lowercase();
    let computed_low = computed.to_lowercase();

    println!("  Algoritmo : {}", algo.to_uppercase().bright_cyan());
    println!("  Esperado  : {}", expected.bright_yellow());
    println!("  Calculado : {}", computed_low.bright_white());

    println!();
    if computed_low == expected {
        println!("  {} Integridade VERIFICADA — arquivo íntegro", "[OK]".bright_green().bold());
    } else {
        println!("  {} Integridade FALHOU — arquivo pode estar corrompido ou adulterado!",
            "[FALHA]".bright_red().bold()
        );
    }

    println!("{}", "─".repeat(65).bright_black());

    Ok(())
}
