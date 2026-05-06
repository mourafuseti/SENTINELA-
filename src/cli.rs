use clap::{Parser, Subcommand, Args};

#[derive(Parser)]
#[command(
    name = "sentinela",
    about = "Suite de segurança para SOC — Network Recon | Log Analyzer | Password | Hash | Crypto",
    version = "0.1.0",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Reconhecimento de rede: port scan, DNS, ping sweep
    Network(NetworkArgs),
    /// Analisador de logs para SIEM: detecta padrões suspeitos
    Logs(LogArgs),
    /// Gerador de senhas, wordlist e verificador de força
    Password(PasswordArgs),
    /// Identificador, gerador e cracker de hashes
    Hash(HashArgs),
    /// Laboratório de criptografia: aprenda, codifique, cifre
    Crypto(CryptoArgs),
    /// Scanner de vulnerabilidades: FTP anon, credenciais padrão, HTTP, SSH, Redis...
    Vuln(VulnArgs),
}

// ─── Network ───────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub cmd: NetworkCmd,
}

#[derive(Subcommand)]
pub enum NetworkCmd {
    /// Varre portas de um host ou range CIDR
    Scan {
        /// Alvo: IP, hostname ou CIDR (ex: 192.168.1.0/24)
        #[arg(short, long)]
        target: String,
        /// Range de portas (ex: 1-1024 ou 80,443,8080)
        #[arg(short, long, default_value = "1-1024")]
        ports: String,
        /// Timeout por porta em milissegundos
        #[arg(long, default_value = "500")]
        timeout: u64,
        /// Threads simultâneas
        #[arg(long, default_value = "200")]
        threads: usize,
    },
    /// Resolução DNS completa: A, AAAA, MX, NS, TXT, CNAME
    Dns {
        /// Domínio alvo (ex: example.com)
        #[arg(short, long)]
        target: String,
        /// Mostrar todos os tipos de registro
        #[arg(short, long)]
        all: bool,
    },
    /// Ping sweep em range de IPs
    Sweep {
        /// Range CIDR (ex: 192.168.1.0/24)
        #[arg(short, long)]
        cidr: String,
        /// Timeout em milissegundos
        #[arg(long, default_value = "1000")]
        timeout: u64,
    },
    /// Banner grabbing em porta específica
    Banner {
        /// Host alvo
        #[arg(short, long)]
        target: String,
        /// Porta
        #[arg(short, long)]
        port: u16,
    },
    /// Scan completo de rede /24: descobre hosts vivos e varre portas de cada um
    Netscan {
        /// Range CIDR (ex: 192.168.1.0/24)
        #[arg(short, long)]
        cidr: String,
        /// Portas a varrer em cada host (ex: 1-1024 ou 22,80,443,3389)
        #[arg(short, long, default_value = "21,22,23,25,53,80,110,135,139,143,443,445,554,1080,1900,3306,3389,5000,5432,5900,7070,8008,8009,8080,8443,8888,9000,9080,9090,62078")]
        ports: String,
        /// Timeout por porta em ms
        #[arg(long, default_value = "400")]
        timeout: u64,
        /// Threads por host
        #[arg(long, default_value = "100")]
        threads: usize,
        /// Exportar resultado como JSON
        #[arg(short, long)]
        output: Option<String>,
    },
}

// ─── Logs ──────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct LogArgs {
    #[command(subcommand)]
    pub cmd: LogCmd,
}

#[derive(Subcommand)]
pub enum LogCmd {
    /// Analisa arquivo de log e detecta padrões suspeitos
    Analyze {
        /// Arquivo de log
        #[arg(short, long)]
        file: String,
        /// Formato: syslog, nginx, apache, auth, json (auto-detect se omitido)
        #[arg(short = 'F', long)]
        format: Option<String>,
        /// Mostrar resumo estatístico
        #[arg(short, long)]
        stats: bool,
        /// Exportar alertas como JSON
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Monitora arquivo de log em tempo real (tail -f com análise)
    Watch {
        /// Arquivo de log
        #[arg(short, long)]
        file: String,
        /// Formato do log
        #[arg(short = 'F', long)]
        format: Option<String>,
    },
    /// Busca padrão/regex em log
    Search {
        /// Arquivo de log
        #[arg(short, long)]
        file: String,
        /// Padrão regex
        #[arg(short, long)]
        pattern: String,
        /// Mostrar N linhas de contexto
        #[arg(short = 'C', long, default_value = "0")]
        context: usize,
    },
}

// ─── Password ──────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct PasswordArgs {
    #[command(subcommand)]
    pub cmd: PasswordCmd,
}

#[derive(Subcommand)]
pub enum PasswordCmd {
    /// Gera senhas aleatórias seguras
    Generate {
        /// Comprimento da senha
        #[arg(short, long, default_value = "16")]
        length: usize,
        /// Quantidade de senhas
        #[arg(short, long, default_value = "1")]
        count: usize,
        /// Incluir maiúsculas
        #[arg(long, default_value = "true")]
        upper: bool,
        /// Incluir números
        #[arg(long, default_value = "true")]
        numbers: bool,
        /// Incluir símbolos
        #[arg(long, default_value = "true")]
        symbols: bool,
        /// Excluir caracteres ambíguos (0,O,l,I)
        #[arg(long)]
        no_ambiguous: bool,
    },
    /// Verifica força de uma senha
    Check {
        /// Senha a analisar
        password: String,
        /// Estimar tempo de crack por força bruta
        #[arg(short, long)]
        estimate: bool,
    },
    /// Gera wordlist baseada em tema/nome/empresa
    Wordlist {
        /// Palavra base (ex: empresa, nome da vítima)
        #[arg(short, long)]
        base: String,
        /// Aplicar mutações leet speak (a→4, e→3, etc)
        #[arg(long)]
        leet: bool,
        /// Adicionar sufixos comuns (anos, !, 123, etc)
        #[arg(long)]
        suffixes: bool,
        /// Arquivo de saída (padrão: stdout)
        #[arg(short, long)]
        output: Option<String>,
        /// Comprimento mínimo
        #[arg(long, default_value = "6")]
        min_len: usize,
        /// Comprimento máximo
        #[arg(long, default_value = "20")]
        max_len: usize,
    },
}

// ─── Hash ──────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct HashArgs {
    #[command(subcommand)]
    pub cmd: HashCmd,
}

#[derive(Subcommand)]
pub enum HashCmd {
    /// Identifica o algoritmo provável de um hash
    Identify {
        /// Hash a identificar
        hash: String,
    },
    /// Gera hash de um texto com algoritmo escolhido
    Generate {
        /// Texto de entrada
        input: String,
        /// Algoritmo: md5, sha1, sha256, sha512, sha3-256
        #[arg(short, long, default_value = "sha256")]
        algo: String,
        /// Ler de arquivo ao invés de string
        #[arg(short, long)]
        file: Option<String>,
    },
    /// Tenta crackear hash com wordlist
    Crack {
        /// Hash alvo
        #[arg(short = 'H', long)]
        hash: String,
        /// Algoritmo: md5, sha1, sha256, sha512 (auto-detect se omitido)
        #[arg(short, long)]
        algo: Option<String>,
        /// Arquivo wordlist
        #[arg(short, long)]
        wordlist: String,
        /// Threads paralelas
        #[arg(short, long, default_value = "4")]
        threads: usize,
    },
    /// Verifica integridade de arquivo por hash
    Verify {
        /// Arquivo
        #[arg(short, long)]
        file: String,
        /// Hash esperado
        #[arg(short = 'H', long)]
        hash: String,
        /// Algoritmo
        #[arg(short, long, default_value = "sha256")]
        algo: String,
    },
}

// ─── Crypto ────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct CryptoArgs {
    #[command(subcommand)]
    pub cmd: CryptoCmd,
}

#[derive(Subcommand)]
pub enum CryptoCmd {
    /// Codifica/decodifica texto (Base64, Hex, URL, ROT13)
    Encode {
        /// Texto de entrada
        input: String,
        /// Esquema: base64, hex, url, rot13, binary
        #[arg(short, long, default_value = "base64")]
        scheme: String,
        /// Decodificar ao invés de codificar
        #[arg(short, long)]
        decode: bool,
    },
    /// Cifra/decifra texto (César, Vigenère, XOR, AES)
    Cipher {
        /// Texto de entrada
        input: String,
        /// Cifra: caesar, vigenere, xor, aes
        #[arg(short, long, default_value = "caesar")]
        cipher: String,
        /// Chave (número para César, string para Vigenère/XOR, hex para AES)
        #[arg(short, long)]
        key: String,
        /// Decifrar ao invés de cifrar
        #[arg(short, long)]
        decrypt: bool,
    },
    /// Modo interativo para aprender criptografia
    Learn {
        /// Tópico: caesar, vigenere, xor, aes, hashing, base64
        #[arg(short, long)]
        topic: Option<String>,
    },
    /// Análise de frequência de caracteres (útil para cifras clássicas)
    Frequency {
        /// Texto cifrado a analisar
        text: String,
    },
}

// ─── Vuln ──────────────────────────────────────────────────────────────────

#[derive(Args)]
pub struct VulnArgs {
    #[command(subcommand)]
    pub cmd: VulnCmd,
}

#[derive(Subcommand)]
pub enum VulnCmd {
    /// Scan de vulnerabilidades em um host (todas as verificações)
    Scan {
        /// Host alvo (IP ou hostname)
        #[arg(short, long)]
        target: String,
        /// Portas a verificar (detecta serviços automaticamente)
        #[arg(short, long, default_value = "21,22,23,25,80,443,445,3306,5432,5900,6379,8080,8443,9000,27017")]
        ports: String,
        /// Timeout de conexão em ms
        #[arg(long, default_value = "3000")]
        timeout: u64,
        /// Exportar relatório como JSON
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Scan de vulns em toda a rede /CIDR
    Netscan {
        /// Range CIDR (ex: 192.168.0.0/24)
        #[arg(short, long)]
        cidr: String,
        /// Timeout de conexão em ms
        #[arg(long, default_value = "2000")]
        timeout: u64,
        /// Exportar relatório como JSON
        #[arg(short, long)]
        output: Option<String>,
    },
}
