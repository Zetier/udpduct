mod agent;
mod cli;
mod protocol;
mod runtime;
mod spec;
mod ssh;
mod tunnel;

use anyhow::Result;

pub async fn run() -> Result<()> {
    let (global, command) = cli::parse()?;
    cli::init_logging(&global);

    match command {
        cli::Command::Client(args) => runtime::run_client(args, global).await,
        cli::Command::Agent(args) => agent::run(args).await,
    }
}
