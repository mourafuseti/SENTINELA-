mod cli;
mod menu;
mod modules;

use anyhow::Result;
use clap::Parser;
use colored::*;

use cli::{Cli, Commands};

#[tokio::main]
async fn main() -> Result<()> {
    // Se não passou argumentos, abre o menu interativo
    if std::env::args().len() == 1 {
        print_banner();
        return menu::run_menu().await;
    }

    print_banner();

    let cli = Cli::parse();

    match cli.command {
        Commands::Network(args) => modules::network::run(args).await?,
        Commands::Logs(args) => modules::logs::run(args).await?,
        Commands::Password(args) => modules::password::run(args)?,
        Commands::Hash(args) => modules::hash::run(args)?,
        Commands::Crypto(args) => modules::crypto::run(args)?,
        Commands::Vuln(args) => modules::vuln::run(args).await?,
    }

    Ok(())
}

fn print_banner() {
    println!("{}", r#"
  ███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗      █████╗
  ██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     ██╔══██╗
  ███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     ███████║
  ╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     ██╔══██║
  ███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗██║  ██║
  ╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═╝
"#.bright_cyan().bold());
    println!("  {} {} | {}",
        "SOC Security Suite".bright_white().bold(),
        "v0.1.0".bright_yellow(),
        "Network • Logs • Password • Hash • Crypto".bright_blue()
    );
    println!("  {}\n", "═".repeat(70).bright_black());
}
