use anyhow::{Result, bail};

use crate::cli::AgentArgs;
use crate::runtime;

pub async fn run(args: AgentArgs) -> Result<()> {
    if !args.stdio {
        bail!("agent mode requires --stdio");
    }
    runtime::run_agent_stdio().await
}
