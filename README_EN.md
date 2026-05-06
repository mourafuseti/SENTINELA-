# SENTINELA — SOC Security Suite

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"/>
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/version-0.1.0-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge"/>
</p>

<p align="center">
  <b>Offensive and defensive security suite for SOC professionals, pentesters, and security enthusiasts.</b><br/>
  Built in Rust — fast, safe, and with no external runtime dependencies.
</p>

---

> [🇧🇷 Português](README.md) | 🇺🇸 English

---

## Overview

**Sentinela** is a modular security toolkit written in Rust, designed for SOC (Security Operations Center) environments and penetration testing activities. It works both as an **interactive menu** and as a **command-line tool**, making it easy to use manually or automate in scripts.

```
sentinela            → opens the interactive menu
sentinela <module>   → direct CLI usage
```

---

## Modules

### Network Recon
Network reconnaissance supporting single hosts and CIDR ranges.

| Command | Description |
|---|---|
| `network scan` | Async TCP port scanner with multi-threading |
| `network dns` | Full DNS resolution: A, AAAA, MX, NS, TXT |
| `network sweep` | Ping sweep across a CIDR range |
| `network banner` | Banner grabbing from TCP services |
| `network netscan` | Full network scan: discovers live hosts then scans ports on each |

```bash
sentinela network scan --target 192.168.1.1 --ports 1-1024
sentinela network netscan --cidr 192.168.0.0/24
sentinela network dns --target example.com
```

---

### Log Analyzer — SIEM
Analyzes log files for attack patterns with 16 built-in detection rules.

| Detected Pattern | Severity |
|---|---|
| SSH Brute Force | High |
| Root login attempt | Critical |
| SQL Injection | Critical |
| XSS / Path Traversal | High |
| Web Shell upload | Critical |
| Scanner detected (Nikto, sqlmap...) | Medium |
| Privilege escalation (sudo) | High |
| /etc/passwd modification | High |

```bash
sentinela logs analyze --file /var/log/auth.log --stats
sentinela logs watch --file /var/log/nginx/access.log
sentinela logs search --file access.log --pattern "sqlmap" -C 2
```

---

### Password Tools
Password generation and analysis with GPU crack time estimation.

```bash
sentinela password generate --length 20 --count 10
sentinela password check "mypassword" --estimate
sentinela password wordlist --base "company" --leet --suffixes -o list.txt
```

- Configurable charset generator (uppercase, numbers, symbols, no ambiguous)
- Strength analysis with entropy calculation and crack time estimate (online / offline / GPU)
- Wordlist with leet speak mutations and common suffixes (123, 2024, !, @...)

---

### Hash Tools
Hash identification, generation, and dictionary attacks.

```bash
sentinela hash identify 5f4dcc3b5aa765d61d8327deb882cf99
sentinela hash generate "text" --algo sha256
sentinela hash crack -H <hash> --wordlist rockyou.txt
sentinela hash verify --file file.iso -H <expected_hash>
```

Supported algorithms: `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SHA3-256`

---

### Crypto Lab
Cryptography laboratory for learning and analysis.

```bash
sentinela crypto encode "Hello World" --scheme base64
sentinela crypto cipher "text" --cipher caesar --key 13
sentinela crypto frequency "KHOOR ZRUOG"
sentinela crypto learn --topic aes
```

| Encoding | Ciphers | Learning Topics |
|---|---|---|
| Base64, Hex, URL | Caesar, Vigenère | AES, Hashing |
| ROT13, Binary | XOR, Atbash | Base64, XOR |
| Reverse | | Caesar, Vigenère |

---

### Vulnerability Scanner
Automated vulnerability checks on hosts and networks.

```bash
sentinela vuln scan --target 192.168.0.1
sentinela vuln netscan --cidr 192.168.0.0/24 --output report.json
```

| Check | Port | Severity |
|---|---|---|
| FTP Anonymous Login | 21 | Critical |
| vsftpd 2.3.4 Backdoor (CVE-2011-2523) | 21 | Critical |
| Telnet open | 23 | Critical |
| Default HTTP credentials (admin:admin...) | 80/8080 | Critical |
| Redis with no authentication | 6379 | Critical |
| MongoDB with no authentication | 27017 | Critical |
| .git / .env exposed | 80/443 | Critical |
| SSHv1 active | 22 | Critical |
| Outdated OpenSSH version (< 7.0) | 22 | High |
| Outdated Apache/IIS version | 80 | High |
| phpMyAdmin / Tomcat Manager exposed | 80/8080 | High |
| HTTP TRACE method enabled | 80 | Medium |
| SMB exposed on network | 445 | Medium |
| VNC exposed | 5900 | Medium |
| Missing security headers (HSTS, CSP, XFO...) | 80/443 | Low/Medium |

---

## Installation

### Requirements
- [Rust](https://rustup.rs/) 1.70+
- Linux (tested on Kali Linux)

### Build and install

```bash
git clone https://github.com/mourafuseti/SENTINELA-.git
cd SENTINELA-
cargo build --release
sudo cp target/release/sentinela /usr/local/bin/
```

### Run directly

```bash
cargo run -- network scan --target 192.168.1.1 --ports 80,443,22
```

---

## Usage

### Interactive menu (recommended for manual use)

```bash
sentinela
```

Navigate with arrow keys, confirm with Enter. All modules available with guided input fields.

### CLI (recommended for scripts and automation)

```bash
# Quick examples
sentinela network netscan --cidr 192.168.0.0/24 --output scan.json
sentinela vuln scan --target 10.0.0.1 --output vuln.json
sentinela logs analyze --file /var/log/auth.log --stats --output alerts.json
sentinela hash crack -H 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
sentinela password generate --length 24 --count 5
```

### Help

```bash
sentinela --help
sentinela network --help
sentinela vuln scan --help
```

---

## Project Structure

```
sentinela/
├── Cargo.toml
└── src/
    ├── main.rs              # Entry point — menu or CLI
    ├── cli.rs               # All command definitions (clap)
    ├── menu.rs              # Interactive menu (dialoguer)
    └── modules/
        ├── network/mod.rs   # Port scan, DNS, sweep, netscan
        ├── logs/mod.rs      # SIEM log analyzer
        ├── password/mod.rs  # Generator, wordlist, strength
        ├── hash/mod.rs      # Identify, generate, crack
        ├── crypto/mod.rs    # Encode, cipher, learn
        └── vuln/mod.rs      # Vulnerability scanner
```

---

## Legal Disclaimer

This tool was developed for educational purposes, cyber defense, and **authorized** penetration testing only. Using it against systems without explicit permission is illegal and unethical. The authors take no responsibility for misuse.

**Use responsibly. Only test what you have authorization to test.**

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Built with Rust and ☕ for the security community</p>
