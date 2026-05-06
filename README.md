# SENTINELA — SOC Security Suite

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white"/>
  <img src="https://img.shields.io/badge/Kali_Linux-557C94?style=for-the-badge&logo=kali-linux&logoColor=white"/>
  <img src="https://img.shields.io/badge/versão-0.1.0-brightgreen?style=for-the-badge"/>
  <img src="https://img.shields.io/badge/licença-MIT-blue?style=for-the-badge"/>
</p>

<p align="center">
  <b>Suite de segurança ofensiva e defensiva para profissionais de SOC, pentesters e entusiastas de segurança digital.</b><br/>
  Construída em Rust — rápida, segura e sem dependências externas de runtime.
</p>

---

> 🇧🇷 Português | [🇺🇸 English](README_EN.md)

---

## Visão Geral

**Sentinela** é uma ferramenta modular de segurança desenvolvida em Rust para uso em ambientes SOC (Security Operations Center) e atividades de pentest. Funciona tanto via **menu interativo** quanto via **linha de comando**, sendo fácil de usar e fácil de automatizar.

```
sentinela            → abre o menu interativo
sentinela <módulo>   → uso direto via CLI
```

---

## Módulos

### Network Recon
Reconhecimento de rede com suporte a hosts únicos e ranges CIDR.

| Comando | Descrição |
|---|---|
| `network scan` | Port scanner TCP assíncrono com múltiplas threads |
| `network dns` | Resolução DNS completa: A, AAAA, MX, NS, TXT |
| `network sweep` | Ping sweep em range CIDR |
| `network banner` | Banner grabbing em serviços TCP |
| `network netscan` | Scan completo de rede: descobre hosts + varre portas de cada um |

```bash
sentinela network scan --target 192.168.1.1 --ports 1-1024
sentinela network netscan --cidr 192.168.0.0/24
sentinela network dns --target example.com
```

---

### Log Analyzer — SIEM
Analisa logs em busca de padrões de ataque com 16 regras de detecção.

| Regra detectada | Severidade |
|---|---|
| Brute Force SSH | Alto |
| Login como root | Crítico |
| SQL Injection | Crítico |
| XSS / Path Traversal | Alto |
| Web Shell upload | Crítico |
| Scanner detectado (Nikto, sqlmap...) | Médio |
| Escalada de privilégio (sudo) | Alto |
| Modificação em /etc/passwd | Alto |

```bash
sentinela logs analyze --file /var/log/auth.log --stats
sentinela logs watch --file /var/log/nginx/access.log
sentinela logs search --file access.log --pattern "sqlmap" -C 2
```

---

### Password Tools
Geração e análise de senhas com estimativa de crack por GPU.

```bash
sentinela password generate --length 20 --count 10
sentinela password check "minhasenha" --estimate
sentinela password wordlist --base "empresa" --leet --suffixes -o lista.txt
```

- Gerador com charset configurável (maiúsculas, números, símbolos, sem ambíguos)
- Análise de força com cálculo de entropia e estimativa de crack (online / offline / GPU)
- Wordlist com mutações leet speak e sufixos comuns (123, 2024, !, @...)

---

### Hash Tools
Identificação, geração e ataque a hashes.

```bash
sentinela hash identify 5f4dcc3b5aa765d61d8327deb882cf99
sentinela hash generate "texto" --algo sha256
sentinela hash crack -H <hash> --wordlist rockyou.txt
sentinela hash verify --file arquivo.iso -H <hash_esperado>
```

Algoritmos suportados: `MD5`, `SHA-1`, `SHA-256`, `SHA-512`, `SHA3-256`

---

### Crypto Lab
Laboratório de criptografia para aprendizado e análise.

```bash
sentinela crypto encode "Hello World" --scheme base64
sentinela crypto cipher "texto" --cipher caesar --key 13
sentinela crypto frequency "KHOOR ZRUOG"
sentinela crypto learn --topic aes
```

| Encoding | Cifras | Tópicos de aprendizado |
|---|---|---|
| Base64, Hex, URL | César, Vigenère | AES, Hashing |
| ROT13, Binary | XOR, Atbash | Base64, XOR |
| Reverse | | César, Vigenère |

---

### Vulnerability Scanner
Verificações automáticas de vulnerabilidades em hosts e redes.

```bash
sentinela vuln scan --target 192.168.0.1
sentinela vuln netscan --cidr 192.168.0.0/24 --output relatorio.json
```

| Check | Porta | Severidade |
|---|---|---|
| FTP Anonymous Login | 21 | Crítico |
| vsftpd 2.3.4 Backdoor (CVE-2011-2523) | 21 | Crítico |
| Telnet aberto | 23 | Crítico |
| Credenciais padrão HTTP (admin:admin...) | 80/8080 | Crítico |
| Redis sem autenticação | 6379 | Crítico |
| MongoDB sem autenticação | 27017 | Crítico |
| .git / .env expostos | 80/443 | Crítico |
| SSHv1 ativo | 22 | Crítico |
| OpenSSH versão antiga (< 7.0) | 22 | Alto |
| Apache/IIS versão obsoleta | 80 | Alto |
| phpMyAdmin / Tomcat Manager | 80/8080 | Alto |
| HTTP TRACE habilitado | 80 | Médio |
| SMB exposto na rede | 445 | Médio |
| VNC exposto | 5900 | Médio |
| Headers de segurança ausentes (HSTS, CSP, XFO...) | 80/443 | Baixo/Médio |

---

## Instalação

### Pré-requisitos
- [Rust](https://rustup.rs/) 1.70+
- Linux (testado em Kali Linux)

### Compilar e instalar

```bash
git clone https://github.com/mourafuseti/SENTINELA-.git
cd SENTINELA-
cargo build --release
sudo cp target/release/sentinela /usr/local/bin/
```

### Usar diretamente

```bash
cargo run -- network scan --target 192.168.1.1 --ports 80,443,22
```

---

## Uso

### Menu interativo (recomendado para uso manual)

```bash
sentinela
```

Navega com as setas do teclado, confirma com Enter. Todos os módulos disponíveis com campos guiados.

### CLI (recomendado para scripts e automação)

```bash
# Exemplos rápidos
sentinela network netscan --cidr 192.168.0.0/24 --output scan.json
sentinela vuln scan --target 10.0.0.1 --output vuln.json
sentinela logs analyze --file /var/log/auth.log --stats --output alertas.json
sentinela hash crack -H 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist rockyou.txt
sentinela password generate --length 24 --count 5
```

### Ajuda

```bash
sentinela --help
sentinela network --help
sentinela vuln scan --help
```

---

## Estrutura do Projeto

```
sentinela/
├── Cargo.toml
└── src/
    ├── main.rs              # Entry point — menu ou CLI
    ├── cli.rs               # Definição de todos os comandos (clap)
    ├── menu.rs              # Menu interativo (dialoguer)
    └── modules/
        ├── network/mod.rs   # Port scan, DNS, sweep, netscan
        ├── logs/mod.rs      # SIEM log analyzer
        ├── password/mod.rs  # Gerador, wordlist, força
        ├── hash/mod.rs      # Identify, generate, crack
        ├── crypto/mod.rs    # Encode, cipher, learn
        └── vuln/mod.rs      # Vulnerability scanner
```

---

## Aviso Legal

Esta ferramenta foi desenvolvida para fins educacionais, defesa cibernética e testes de penetração **autorizados**. O uso contra sistemas sem permissão expressa é ilegal e antiético. Os autores não se responsabilizam pelo uso indevido.

**Use com responsabilidade. Só teste o que você tem autorização para testar.**

---

## Licença

MIT License — veja [LICENSE](LICENSE) para detalhes.

---

<p align="center">Feito com Rust e ☕ para a comunidade de segurança</p>
