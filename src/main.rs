use clap::{Parser, Subcommand};

mod commands;

#[derive(Parser)]
#[command(
    name = "rustytools",
    about = "Network & System admin debug tool",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Network diagnostics and configuration
    Net {
        #[command(subcommand)]
        command: commands::network::NetCommands,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Net { command } => commands::network::run(command).await,
    }
}
