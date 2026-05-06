use anyhow::Result;
use colored::*;
use std::collections::HashMap;

use crate::cli::{CryptoArgs, CryptoCmd};

pub fn run(args: CryptoArgs) -> Result<()> {
    match args.cmd {
        CryptoCmd::Encode { input, scheme, decode } => {
            encode_decode(&input, &scheme, decode)?;
        }
        CryptoCmd::Cipher { input, cipher, key, decrypt } => {
            apply_cipher(&input, &cipher, &key, decrypt)?;
        }
        CryptoCmd::Learn { topic } => {
            learn_mode(topic.as_deref())?;
        }
        CryptoCmd::Frequency { text } => {
            frequency_analysis(&text)?;
        }
    }
    Ok(())
}

// ─── Encode / Decode ──────────────────────────────────────────────────────

fn encode_decode(input: &str, scheme: &str, decode: bool) -> Result<()> {
    let mode = if decode { "Decodificando" } else { "Codificando" };

    println!("{} {} via {}",
        "[*]".bright_blue().bold(),
        mode.bright_white(),
        scheme.to_uppercase().bright_yellow()
    );
    println!("{}", "─".repeat(60).bright_black());

    let result = match scheme.to_lowercase().as_str() {
        "base64" => {
            use base64::Engine;
            if decode {
                let cleaned = input.replace('\n', "").replace('\r', "");
                let bytes = base64::engine::general_purpose::STANDARD.decode(cleaned.trim())
                    .map_err(|e| anyhow::anyhow!("Base64 inválido: {}", e))?;
                String::from_utf8_lossy(&bytes).to_string()
            } else {
                base64::engine::general_purpose::STANDARD.encode(input)
            }
        }
        "hex" => {
            if decode {
                let bytes = hex::decode(input.replace(' ', "").replace("0x", ""))
                    .map_err(|e| anyhow::anyhow!("Hex inválido: {}", e))?;
                String::from_utf8_lossy(&bytes).to_string()
            } else {
                hex::encode(input)
            }
        }
        "url" => {
            if decode {
                url_decode(input)
            } else {
                url_encode(input)
            }
        }
        "rot13" => {
            rot13(input)
        }
        "binary" => {
            if decode {
                binary_to_text(input)?
            } else {
                text_to_binary(input)
            }
        }
        "reverse" => {
            input.chars().rev().collect()
        }
        _ => anyhow::bail!("Esquema desconhecido: {}. Opções: base64, hex, url, rot13, binary, reverse", scheme),
    };

    println!("  {} {}", "Input  :".bright_black(), input.bright_white());
    println!("  {} {}", "Output :".bright_black(), result.bright_green().bold());
    println!("{}", "─".repeat(60).bright_black());

    Ok(())
}

fn rot13(input: &str) -> String {
    input.chars().map(|c| {
        match c {
            'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
            'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
            _ => c,
        }
    }).collect()
}

fn url_encode(input: &str) -> String {
    let mut out = String::new();
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", byte));
            }
        }
    }
    out
}

fn url_decode(input: &str) -> String {
    let mut out = Vec::new();
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(&input[i+1..i+3], 16) {
                out.push(b);
                i += 3;
                continue;
            }
        } else if bytes[i] == b'+' {
            out.push(b' ');
            i += 1;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn text_to_binary(input: &str) -> String {
    input.bytes().map(|b| format!("{:08b}", b)).collect::<Vec<_>>().join(" ")
}

fn binary_to_text(input: &str) -> Result<String> {
    let chars: Result<Vec<u8>, _> = input.split_whitespace()
        .map(|b| u8::from_str_radix(b, 2))
        .collect();
    Ok(String::from_utf8_lossy(&chars.map_err(|_| anyhow::anyhow!("Binário inválido"))?).to_string())
}

// ─── Cifras ───────────────────────────────────────────────────────────────

fn apply_cipher(input: &str, cipher: &str, key: &str, decrypt: bool) -> Result<()> {
    let mode = if decrypt { "Decifrar" } else { "Cifrar" };

    println!("{} {} com {} | chave: {}",
        "[*]".bright_blue().bold(),
        mode.bright_white(),
        cipher.to_uppercase().bright_yellow(),
        key.bright_cyan()
    );
    println!("{}", "─".repeat(60).bright_black());

    let result = match cipher.to_lowercase().as_str() {
        "caesar" => {
            let shift: u8 = key.parse().map_err(|_| anyhow::anyhow!("Chave César deve ser número 0-25"))?;
            if shift > 25 { anyhow::bail!("Shift deve ser 0-25"); }
            caesar_cipher(input, shift, decrypt)
        }
        "vigenere" => {
            vigenere_cipher(input, key, decrypt)
        }
        "xor" => {
            let key_byte: u8 = if key.starts_with("0x") {
                u8::from_str_radix(&key[2..], 16)?
            } else {
                key.parse().map_err(|_| anyhow::anyhow!("Chave XOR deve ser número 0-255 ou hex 0xNN"))?
            };
            let result_bytes: Vec<u8> = input.bytes().map(|b| b ^ key_byte).collect();
            let printable: String = result_bytes.iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();
            format!("{}\n  Hex: {}", printable, hex::encode(&result_bytes))
        }
        "atbash" => {
            atbash_cipher(input)
        }
        _ => anyhow::bail!("Cifra desconhecida: {}. Opções: caesar, vigenere, xor, atbash", cipher),
    };

    println!("  {} {}", "Input  :".bright_black(), input.bright_white());
    println!("  {} {}", "Output :".bright_black(), result.bright_green().bold());

    if cipher == "caesar" && !decrypt {
        println!("\n  {} Todas as rotações:", "Dica:".bright_yellow());
        let shift: u8 = key.parse().unwrap_or(0);
        let _ = shift;
        println!("  {}", "use 'sentinela crypto learn --topic caesar' para ver análise completa".bright_black().italic());
    }

    println!("{}", "─".repeat(60).bright_black());

    Ok(())
}

fn caesar_cipher(input: &str, shift: u8, decrypt: bool) -> String {
    let s = if decrypt { (26 - shift) % 26 } else { shift };
    input.chars().map(|c| {
        match c {
            'A'..='Z' => (((c as u8 - b'A' + s) % 26) + b'A') as char,
            'a'..='z' => (((c as u8 - b'a' + s) % 26) + b'a') as char,
            _ => c,
        }
    }).collect()
}

fn vigenere_cipher(input: &str, key: &str, decrypt: bool) -> String {
    let key_lower: Vec<u8> = key.to_lowercase().bytes()
        .filter(|b| b.is_ascii_alphabetic())
        .collect();
    if key_lower.is_empty() { return input.to_string(); }

    let mut key_idx = 0;
    input.chars().map(|c| {
        if c.is_ascii_alphabetic() {
            let k = (key_lower[key_idx % key_lower.len()] - b'a') as u8;
            key_idx += 1;
            let base = if c.is_uppercase() { b'A' } else { b'a' };
            let c_val = c as u8 - base;
            let result = if decrypt {
                (c_val + 26 - k) % 26
            } else {
                (c_val + k) % 26
            };
            (result + base) as char
        } else {
            c
        }
    }).collect()
}

fn atbash_cipher(input: &str) -> String {
    input.chars().map(|c| {
        match c {
            'A'..='Z' => (b'Z' - (c as u8 - b'A')) as char,
            'a'..='z' => (b'z' - (c as u8 - b'a')) as char,
            _ => c,
        }
    }).collect()
}

// ─── Análise de Frequência ────────────────────────────────────────────────

fn frequency_analysis(text: &str) -> Result<()> {
    println!("{} {}", "[*]".bright_blue().bold(), "Análise de Frequência".bright_white().bold());
    println!("{}", "─".repeat(65).bright_black());

    let text_upper = text.to_uppercase();
    let letters: Vec<char> = text_upper.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let total = letters.len();

    if total == 0 {
        println!("{} Nenhuma letra encontrada no texto", "[!]".bright_yellow());
        return Ok(());
    }

    let mut freq: HashMap<char, usize> = HashMap::new();
    for c in &letters {
        *freq.entry(*c).or_insert(0) += 1;
    }

    let mut freq_vec: Vec<(char, usize)> = freq.into_iter().collect();
    freq_vec.sort_by(|a, b| b.1.cmp(&a.1));

    // Frequência do Inglês para comparação
    let english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ";

    println!("  Total de letras: {}", total.to_string().bright_yellow());
    println!("  Frequência em Inglês: {}", english_freq.bright_black());
    println!();
    println!("  {:<6} {:>8} {:>8}   {}",
        "Letra".bright_white().bold(),
        "Contagem".bright_white().bold(),
        "Freq%".bright_white().bold(),
        "Barra".bright_white().bold()
    );
    println!("  {}", "─".repeat(55).bright_black());

    for (ch, count) in &freq_vec {
        let pct = (*count as f64 / total as f64) * 100.0;
        let bar_len = (pct * 2.0) as usize;
        let bar = "█".repeat(bar_len);

        let color_bar = match bar_len {
            0..=5  => bar.bright_black(),
            6..=10 => bar.bright_blue(),
            11..=15 => bar.bright_cyan(),
            16..=20 => bar.bright_yellow(),
            _      => bar.bright_green().bold(),
        };

        println!("  {:<6} {:>8} {:>7.1}%   {}",
            ch.to_string().bright_white().bold(),
            count.to_string().bright_yellow(),
            pct,
            color_bar
        );
    }

    println!();
    println!("  {}", "Dica de decifragem:".bright_cyan().bold());

    if let Some((most_common, _)) = freq_vec.first() {
        let shift_to_e = ((*most_common as u8 - b'E') % 26) as i32;
        println!("  Se cifra César: a letra mais comum '{}' pode ser 'E'",
            most_common.to_string().bright_yellow()
        );
        println!("  Shift provável: {} (tente: sentinela crypto cipher --cipher caesar --key {})",
            shift_to_e.to_string().bright_green(),
            shift_to_e.to_string().bright_green()
        );
    }

    println!("{}", "─".repeat(65).bright_black());

    Ok(())
}

// ─── Modo Aprender ────────────────────────────────────────────────────────

fn learn_mode(topic: Option<&str>) -> Result<()> {
    match topic {
        None => print_learn_menu(),
        Some("caesar") => learn_caesar(),
        Some("vigenere") => learn_vigenere(),
        Some("xor") => learn_xor(),
        Some("base64") => learn_base64(),
        Some("hashing") => learn_hashing(),
        Some("aes") => learn_aes(),
        Some(t) => println!("{} Tópico '{}' não encontrado. Tente: caesar, vigenere, xor, base64, hashing, aes",
            "[!]".bright_yellow(), t),
    }
    Ok(())
}

fn print_learn_menu() {
    println!("{}", r#"
  ╔══════════════════════════════════════════════════════════╗
  ║         LABORATÓRIO DE CRIPTOGRAFIA — Sentinela          ║
  ╚══════════════════════════════════════════════════════════╝
"#.bright_cyan());

    let topics = vec![
        ("caesar",   "Cifra de César       — deslocamento do alfabeto"),
        ("vigenere", "Cifra de Vigenère    — chave polialfabética"),
        ("xor",      "XOR Cipher           — operação lógica XOR"),
        ("base64",   "Base64               — codificação, não criptografia"),
        ("hashing",  "Hash Functions       — MD5, SHA, bcrypt"),
        ("aes",      "AES                  — Advanced Encryption Standard"),
    ];

    println!("  {}", "Tópicos disponíveis:".bright_white().bold());
    for (key, desc) in &topics {
        println!("    {} {} — {}",
            "▸".bright_cyan(),
            format!("sentinela crypto learn --topic {}", key).bright_yellow(),
            desc.bright_white()
        );
    }

    println!("\n  {}", "Exemplos práticos:".bright_white().bold());
    println!("    {}", "sentinela crypto encode 'Hello World' --scheme base64".bright_black());
    println!("    {}", "sentinela crypto cipher 'Attack at dawn' --cipher caesar --key 13".bright_black());
    println!("    {}", "sentinela crypto frequency 'KHOOR ZRUOG'".bright_black());
}

fn learn_caesar() {
    println!("{}", "\n  ═══ CIFRA DE CÉSAR ═══\n".bright_cyan().bold());
    println!("  {}", "O quê é?".bright_white().bold());
    println!("  Uma das cifras mais antigas (usada por Júlio César ~50 a.C.).");
    println!("  Cada letra é deslocada N posições no alfabeto.\n");

    println!("  {}", "Como funciona:".bright_white().bold());
    println!("  Plaintext : {}", "HELLO".bright_green());
    println!("  Shift     : {}", "3".bright_yellow());
    println!("  Ciphertext: {}", "KHOOR".bright_red());
    println!("  (H+3=K, E+3=H, L+3=O, L+3=O, O+3=R)\n");

    println!("  {}", "Alfabeto deslocado (shift 3):".bright_white().bold());
    let plain: String  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".to_string();
    let cipher: String = "DEFGHIJKLMNOPQRSTUVWXYZABC".to_string();
    println!("  Plain : {}", plain.bright_green());
    println!("  Cifra : {}", cipher.bright_red());

    println!("\n  {}", "Fraquezas:".bright_white().bold());
    println!("  ● Apenas 25 combinações possíveis");
    println!("  ● Análise de frequência revela o shift");
    println!("  ● Não use para dados reais!\n");

    println!("  {}", "Experimente:".bright_white().bold());
    println!("  {}", "sentinela crypto cipher 'Hello World' --cipher caesar --key 13".bright_yellow());
    println!("  {}", "sentinela crypto frequency 'KHOOR ZRUOG'  # descubra o shift".bright_yellow());
}

fn learn_vigenere() {
    println!("{}", "\n  ═══ CIFRA DE VIGENÈRE ═══\n".bright_cyan().bold());
    println!("  {}", "O quê é?".bright_white().bold());
    println!("  Evolução da cifra de César com uma chave polialfabética.");
    println!("  Cada letra usa um shift diferente baseado na chave.\n");

    println!("  {}", "Como funciona:".bright_white().bold());
    println!("  Plaintext : {}", "HELLO".bright_green());
    println!("  Chave     : {}", "KEY".bright_yellow());
    println!("  Shifts    : K=10, E=4, Y=24, K=10, E=4");
    println!("  Ciphertext: {}", "RIJVS".bright_red());

    println!("\n  {}", "Fraquezas:".bright_white().bold());
    println!("  ● Análise de índice de coincidência revela tamanho da chave");
    println!("  ● Com chave curta, é vulnerável (teste de Kasiski)\n");

    println!("  {}", "Experimente:".bright_white().bold());
    println!("  {}", "sentinela crypto cipher 'Hello World' --cipher vigenere --key SECRET".bright_yellow());
}

fn learn_xor() {
    println!("{}", "\n  ═══ XOR CIPHER ═══\n".bright_cyan().bold());
    println!("  {}", "O quê é?".bright_white().bold());
    println!("  Usa a operação lógica XOR (ou exclusivo) bit a bit.");
    println!("  Propriedade chave: A XOR B XOR B = A\n");

    println!("  {}", "Tabela verdade XOR:".bright_white().bold());
    println!("  0 XOR 0 = 0");
    println!("  0 XOR 1 = 1");
    println!("  1 XOR 0 = 1");
    println!("  1 XOR 1 = {}", "0  ← mesma chave cancela!".bright_yellow());

    println!("\n  {}", "Exemplo:".bright_white().bold());
    println!("  'A' = 01000001  XOR  42 = 00101010  =  01101011 = 'k'");
    println!("  'k' = 01101011  XOR  42 = 00101010  =  01000001 = {} ← decifrado!", "'A'".bright_green());

    println!("\n  {}", "Uso real:".bright_white().bold());
    println!("  ● Base de muitos algoritmos modernos (AES internamente)");
    println!("  ● Malware frequentemente usa XOR para ofuscar strings\n");

    println!("  {}", "Experimente:".bright_white().bold());
    println!("  {}", "sentinela crypto cipher 'Hello' --cipher xor --key 42".bright_yellow());
}

fn learn_base64() {
    println!("{}", "\n  ═══ BASE64 ═══\n".bright_cyan().bold());
    println!("  {}", "ATENÇÃO: Base64 NÃO é criptografia!".bright_red().bold());
    println!("  É uma codificação para representar dados binários em texto ASCII.\n");

    println!("  {}", "Como funciona:".bright_white().bold());
    println!("  Agrupa bits em blocos de 6 e mapeia para 64 caracteres:");
    println!("  A-Z (0-25), a-z (26-51), 0-9 (52-61), + (62), / (63)\n");

    println!("  {}", "Exemplo:".bright_white().bold());
    println!("  'Man' → 01001101 01100001 01101110");
    println!("  Grupos de 6: 010011 010110 000101 101110");
    println!("  Índices: 19, 22, 5, 46 → {}", "TWFu".bright_green());

    println!("\n  {}", "Uso em segurança:".bright_white().bold());
    println!("  ● Transporte de dados binários (imagens, certificados)");
    println!("  ● Ofuscação básica em malware (facilmente detectável)");
    println!("  ● Tokens JWT, cookies\n");

    println!("  {}", "Experimente:".bright_white().bold());
    println!("  {}", "sentinela crypto encode 'Hello World' --scheme base64".bright_yellow());
    println!("  {}", "sentinela crypto encode 'SGVsbG8gV29ybGQ=' --scheme base64 --decode".bright_yellow());
}

fn learn_hashing() {
    println!("{}", "\n  ═══ HASH FUNCTIONS ═══\n".bright_cyan().bold());
    println!("  {}", "O quê é?".bright_white().bold());
    println!("  Função unidirecional: entrada → saída fixa. Irreversível.\n");

    println!("  {}", "Algoritmos comuns:".bright_white().bold());
    let algos = vec![
        ("MD5",     "128 bits", "32 hex", "OBSOLETO — colisões conhecidas"),
        ("SHA-1",   "160 bits", "40 hex", "DEPRECIADO — colisão em 2017"),
        ("SHA-256", "256 bits", "64 hex", "Seguro — padrão atual"),
        ("SHA-512", "512 bits", "128hex", "Mais seguro — mais lento"),
        ("bcrypt",  "variável", "60 chr", "Ideal para senhas — slow hash"),
        ("Argon2",  "variável", "variável","Mais moderno para senhas"),
    ];

    for (algo, bits, len, note) in &algos {
        let note_colored = if note.contains("OBSOLETO") || note.contains("DEPRECIADO") {
            note.bright_red()
        } else if note.contains("Ideal") || note.contains("moderno") {
            note.bright_green()
        } else {
            note.bright_white()
        };
        println!("  {:<10} {:<12} {:<10} {}",
            algo.bright_cyan(), bits.bright_black(), len.bright_black(), note_colored
        );
    }

    println!("\n  {}", "Propriedades de um bom hash:".bright_white().bold());
    println!("  ● Determinístico: mesma entrada = mesma saída");
    println!("  ● Efeito avalanche: 1 bit muda → ~50% dos bits mudam");
    println!("  ● Resistência a pré-imagem: hash → input impossível");
    println!("  ● Resistência a colisão: dois inputs → mesmo hash impossível\n");

    println!("  {}", "Experimente:".bright_white().bold());
    println!("  {}", "sentinela hash generate 'senha123' --algo md5".bright_yellow());
    println!("  {}", "sentinela hash generate 'senha123' --algo sha256".bright_yellow());
    println!("  {}", "sentinela hash identify 5f4dcc3b5aa765d61d8327deb882cf99".bright_yellow());
}

fn learn_aes() {
    println!("{}", "\n  ═══ AES — ADVANCED ENCRYPTION STANDARD ═══\n".bright_cyan().bold());
    println!("  {}", "O quê é?".bright_white().bold());
    println!("  Padrão mundial de criptografia simétrica desde 2001 (NIST).");
    println!("  Também conhecido como Rijndael.\n");

    println!("  {}", "Características:".bright_white().bold());
    println!("  ● Chaves: 128, 192 ou 256 bits");
    println!("  ● Bloco: 128 bits (16 bytes)");
    println!("  ● Rounds: 10 (AES-128), 12 (AES-192), 14 (AES-256)\n");

    println!("  {}", "Modos de operação:".bright_white().bold());
    let modes = vec![
        ("ECB", "Electronic Codebook   — NUNCA USE! Padrões visíveis"),
        ("CBC", "Cipher Block Chaining — Padrão histórico com IV"),
        ("CTR", "Counter Mode          — Stream cipher, paralelizável"),
        ("GCM", "Galois/Counter Mode   — Autenticado, recomendado"),
        ("CCM", "Counter + CBC-MAC     — Alternativa ao GCM"),
    ];

    for (mode, desc) in &modes {
        let colored_desc = if desc.contains("NUNCA") {
            desc.bright_red().bold()
        } else if desc.contains("recomendado") {
            desc.bright_green()
        } else {
            desc.bright_white()
        };
        println!("  {:<6} {}", mode.bright_cyan(), colored_desc);
    }

    println!("\n  {}", "Pipeline interno (1 round):".bright_white().bold());
    println!("  SubBytes → ShiftRows → MixColumns → AddRoundKey");

    println!("\n  {}", "Onde é usado?".bright_white().bold());
    println!("  ● TLS/HTTPS (AES-128-GCM ou AES-256-GCM)");
    println!("  ● Criptografia de disco (BitLocker, LUKS)");
    println!("  ● VPNs (OpenVPN, WireGuard)");
    println!("  ● WiFi WPA2/WPA3");

    println!("\n  {}", "Segurança:".bright_white().bold());
    println!("  AES-256 nunca foi quebrado por força bruta.");
    println!("  2^256 tentativas ≈ {} anos com GPU moderna", "10^{57}".bright_yellow());
}
