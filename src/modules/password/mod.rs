use anyhow::Result;
use colored::*;
use rand::Rng;
use std::collections::HashSet;

use crate::cli::{PasswordArgs, PasswordCmd};

pub fn run(args: PasswordArgs) -> Result<()> {
    match args.cmd {
        PasswordCmd::Generate { length, count, upper, numbers, symbols, no_ambiguous } => {
            generate_passwords(length, count, upper, numbers, symbols, no_ambiguous)?;
        }
        PasswordCmd::Check { password, estimate } => {
            check_password_strength(&password, estimate)?;
        }
        PasswordCmd::Wordlist { base, leet, suffixes, output, min_len, max_len } => {
            generate_wordlist(&base, leet, suffixes, output.as_deref(), min_len, max_len)?;
        }
    }
    Ok(())
}

// ─── Gerador de Senhas ────────────────────────────────────────────────────

fn generate_passwords(
    length: usize,
    count: usize,
    upper: bool,
    numbers: bool,
    symbols: bool,
    no_ambiguous: bool,
) -> Result<()> {
    let ambiguous: HashSet<char> = "0Ol1I".chars().collect();

    let mut charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
    if upper    { charset.extend("ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars()); }
    if numbers  { charset.extend("0123456789".chars()); }
    if symbols  { charset.extend("!@#$%^&*()_+-=[]{}|;:,.<>?".chars()); }

    if no_ambiguous {
        charset.retain(|c| !ambiguous.contains(c));
    }

    if charset.is_empty() {
        anyhow::bail!("Conjunto de caracteres vazio — habilite pelo menos uma categoria");
    }

    println!("{} {} {}",
        "[*]".bright_blue().bold(),
        "Gerando".bright_white(),
        format!("{} senha(s) de {} caracteres", count, length).bright_yellow()
    );
    println!("{}", "─".repeat(50).bright_black());

    let mut rng = rand::thread_rng();

    for i in 1..=count {
        let password: String = (0..length)
            .map(|_| charset[rng.gen_range(0..charset.len())])
            .collect();

        let strength = estimate_strength(&password);
        println!("  {} {}  {}",
            format!("{:>3}.", i).bright_black(),
            password.bright_white().bold(),
            strength_badge(&strength)
        );
    }

    println!("{}", "─".repeat(50).bright_black());
    println!("  Charset: {} {} {} {}",
        if upper    { "A-Z".bright_green() } else { "A-Z".bright_black() },
        if numbers  { "0-9".bright_green() } else { "0-9".bright_black() },
        if symbols  { "!@#".bright_green() } else { "!@#".bright_black() },
        if no_ambiguous { "(sem ambíguos)".bright_yellow() } else { "".bright_black() }
    );

    Ok(())
}

// ─── Verificador de Força ─────────────────────────────────────────────────

#[derive(Debug)]
struct StrengthResult {
    score: u8,       // 0-100
    label: &'static str,
    entropy: f64,
    issues: Vec<&'static str>,
    suggestions: Vec<&'static str>,
}

fn estimate_strength(password: &str) -> StrengthResult {
    let len = password.len();
    let has_lower  = password.chars().any(|c| c.is_lowercase());
    let has_upper  = password.chars().any(|c| c.is_uppercase());
    let has_digit  = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

    // Calcula entropia
    let charset_size: f64 = {
        let mut s = 0.0f64;
        if has_lower  { s += 26.0; }
        if has_upper  { s += 26.0; }
        if has_digit  { s += 10.0; }
        if has_symbol { s += 32.0; }
        s.max(26.0)
    };
    let entropy = (len as f64) * charset_size.log2();

    // Penalidades
    let mut issues = Vec::new();
    let mut suggestions = Vec::new();
    let mut score: i32 = 0;

    // Comprimento
    score += match len {
        0..=5   => { issues.push("Muito curta"); -10 }
        6..=7   => { issues.push("Curta demais"); 10 }
        8..=11  => 25,
        12..=15 => 35,
        16..=19 => 45,
        _       => 50,
    };

    if len < 12 { suggestions.push("Use pelo menos 12 caracteres"); }

    // Diversidade
    if has_lower  { score += 10; }
    if has_upper  { score += 10; }
    if has_digit  { score += 10; }
    if has_symbol { score += 20; }

    if !has_upper  { suggestions.push("Adicione letras maiúsculas"); }
    if !has_digit  { suggestions.push("Adicione números"); }
    if !has_symbol { suggestions.push("Adicione símbolos (!@#$...)"); }

    // Padrões fracos
    let lower = password.to_lowercase();
    let common = ["password","senha","123456","qwerty","admin","letmein","welcome","monkey","dragon"];
    if common.iter().any(|p| lower.contains(p)) {
        score -= 20;
        issues.push("Contém padrão muito comum");
    }

    // Repetição
    let chars: Vec<char> = password.chars().collect();
    let repeating = chars.windows(3).any(|w| w[0] == w[1] && w[1] == w[2]);
    if repeating {
        score -= 10;
        issues.push("Possui caracteres repetidos em sequência");
    }

    // Sequências simples
    let sequential = chars.windows(3).any(|w| {
        let a = w[0] as i32;
        let b = w[1] as i32;
        let c = w[2] as i32;
        (b - a == 1 && c - b == 1) || (a - b == 1 && b - c == 1)
    });
    if sequential {
        score -= 10;
        issues.push("Possui sequências óbvias (abc, 123)");
        suggestions.push("Evite sequências como abc ou 123");
    }

    let score = score.max(0).min(100) as u8;

    let label = match score {
        0..=19  => "Muito Fraca",
        20..=39 => "Fraca",
        40..=59 => "Razoável",
        60..=79 => "Forte",
        80..=89 => "Muito Forte",
        _       => "Excelente",
    };

    StrengthResult { score, label, entropy, issues, suggestions }
}

fn strength_badge(r: &StrengthResult) -> ColoredString {
    let s = format!("[{}|{}%]", r.label, r.score);
    match r.score {
        0..=19  => s.bright_red().bold(),
        20..=39 => s.red(),
        40..=59 => s.bright_yellow(),
        60..=79 => s.green(),
        _       => s.bright_green().bold(),
    }
}

fn check_password_strength(password: &str, estimate_crack: bool) -> Result<()> {
    let result = estimate_strength(password);

    println!("{} {}", "[*]".bright_blue().bold(), "Análise de Senha".bright_white().bold());
    println!("{}", "─".repeat(55).bright_black());
    println!("  Senha     : {}", "*".repeat(password.len()).bright_black());
    println!("  Força     : {} ({}%)", strength_badge(&result), result.score);
    println!("  Entropia  : {:.1} bits", result.entropy);
    println!("  Comprimento: {} caracteres", password.len());

    if !result.issues.is_empty() {
        println!("\n  {}:", "Problemas".bright_red().bold());
        for issue in &result.issues {
            println!("    {} {}", "✗".bright_red(), issue.bright_white());
        }
    }

    if !result.suggestions.is_empty() {
        println!("\n  {}:", "Sugestões".bright_yellow().bold());
        for sug in &result.suggestions {
            println!("    {} {}", "→".bright_yellow(), sug.bright_white());
        }
    }

    if estimate_crack {
        println!("\n  {}:", "Estimativa de Crack".bright_cyan().bold());
        let crack_time = estimate_crack_time(result.entropy);
        println!("    {} {}", "Força bruta online  :".bright_black(), crack_time.online.bright_yellow());
        println!("    {} {}", "Força bruta offline :".bright_black(), crack_time.offline.bright_yellow());
        println!("    {} {}", "GPU moderna (RTX4090):".bright_black(), crack_time.gpu.bright_yellow());
        println!("    {}", "(estimativas são aproximações; depende do hash e defesas)".bright_black().italic());
    }

    println!("{}", "─".repeat(55).bright_black());

    Ok(())
}

struct CrackTime {
    online: String,
    offline: String,
    gpu: String,
}

fn estimate_crack_time(entropy: f64) -> CrackTime {
    let combinations = 2f64.powf(entropy);

    // Tentativas por segundo por contexto
    let online_rate = 100.0;           // 100/s com rate limiting
    let offline_rate = 1_000_000.0;    // 1M/s CPU
    let gpu_rate = 10_000_000_000.0;   // 10B/s GPU moderna

    CrackTime {
        online:  format_seconds(combinations / online_rate / 2.0),
        offline: format_seconds(combinations / offline_rate / 2.0),
        gpu:     format_seconds(combinations / gpu_rate / 2.0),
    }
}

fn format_seconds(secs: f64) -> String {
    if secs < 1.0        { return "menos de 1 segundo".into(); }
    if secs < 60.0       { return format!("{:.0} segundos", secs); }
    if secs < 3600.0     { return format!("{:.0} minutos", secs / 60.0); }
    if secs < 86400.0    { return format!("{:.0} horas", secs / 3600.0); }
    if secs < 2_592_000.0 { return format!("{:.0} dias", secs / 86400.0); }
    if secs < 31_536_000.0 { return format!("{:.0} meses", secs / 2_592_000.0); }
    let years = secs / 31_536_000.0;
    if years < 1_000.0   { return format!("{:.0} anos", years); }
    if years < 1_000_000.0 { return format!("{:.0} mil anos", years / 1_000.0); }
    format!("{:.2e} anos", years)
}

// ─── Gerador de Wordlist ──────────────────────────────────────────────────

fn generate_wordlist(
    base: &str,
    apply_leet: bool,
    apply_suffixes: bool,
    output: Option<&str>,
    min_len: usize,
    max_len: usize,
) -> Result<()> {
    let mut words: HashSet<String> = HashSet::new();

    // Variações de capitalização
    let variations = capitalize_variations(base);
    for var in &variations {
        words.insert(var.clone());
    }

    // Leet speak
    if apply_leet {
        let mut leet_words = Vec::new();
        for word in &words.clone() {
            leet_words.push(apply_leet_transform(word));
        }
        words.extend(leet_words);
    }

    // Sufixos comuns
    if apply_suffixes {
        let base_words: Vec<String> = words.iter().cloned().collect();
        let suffixes = vec![
            "123", "1234", "12345", "123456",
            "!", "!!", "!@#",
            "2020", "2021", "2022", "2023", "2024", "2025",
            "@2024", "@2025",
            "01", "10",
            "#1", "@1",
            "pass", "senha", "pwd",
        ];
        for word in &base_words {
            for suffix in &suffixes {
                words.insert(format!("{}{}", word, suffix));
                words.insert(format!("{}{}", suffix, word));
            }
        }
    }

    // Filtra por comprimento
    let mut filtered: Vec<String> = words.into_iter()
        .filter(|w| w.len() >= min_len && w.len() <= max_len)
        .collect();
    filtered.sort();

    let total = filtered.len();

    if let Some(out_path) = output {
        use std::io::Write;
        let mut f = std::fs::File::create(out_path)?;
        for word in &filtered {
            writeln!(f, "{}", word)?;
        }
        println!("{} {} palavras salvas em {}",
            "[+]".bright_green().bold(),
            total.to_string().bright_yellow(),
            out_path.bright_white()
        );
    } else {
        println!("{} {} {}",
            "[*]".bright_blue().bold(),
            "Wordlist gerada:".bright_white(),
            format!("{} palavras", total).bright_yellow()
        );
        println!("{}", "─".repeat(50).bright_black());
        for (i, word) in filtered.iter().enumerate() {
            println!("  {:>4}. {}", (i + 1).to_string().bright_black(), word.bright_white());
            if i >= 49 && total > 50 {
                println!("  {}",
                    format!("... e mais {} palavras (use -o arquivo.txt para salvar tudo)", total - 50)
                    .bright_black().italic()
                );
                break;
            }
        }
        println!("{}", "─".repeat(50).bright_black());
        println!("  Dica: use {} para salvar a lista completa", "-o wordlist.txt".bright_yellow());
    }

    Ok(())
}

fn capitalize_variations(word: &str) -> Vec<String> {
    let lower = word.to_lowercase();
    let upper = word.to_uppercase();
    let title = {
        let mut s = lower.clone();
        if let Some(c) = s.get_mut(0..1) {
            c.make_ascii_uppercase();
        }
        s
    };
    vec![lower, upper, title, word.to_string()]
}

fn apply_leet_transform(word: &str) -> String {
    word.chars().map(|c| match c {
        'a' | 'A' => '4',
        'e' | 'E' => '3',
        'i' | 'I' => '1',
        'o' | 'O' => '0',
        's' | 'S' => '5',
        't' | 'T' => '7',
        'l' | 'L' => '1',
        'g' | 'G' => '9',
        _ => c,
    }).collect()
}
