use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{ArgAction, Args, Parser};
use tracing_subscriber::EnvFilter;

use crate::spec::{ForwardSpec, IpFamily, ListenSide, parse_forward_spec};

#[derive(Debug, Clone, Args)]
pub struct GlobalOptions {
    #[arg(short = 'v', action = ArgAction::Count, global = true)]
    pub verbose: u8,
    #[arg(short = 'q', action = ArgAction::SetTrue, global = true)]
    pub quiet: bool,
}

#[derive(Debug)]
pub enum Command {
    Client(Box<ClientArgs>),
    Agent(AgentArgs),
}

#[derive(Debug, Parser)]
#[command(author, version, about)]
struct ClientCli {
    #[command(flatten)]
    global: GlobalOptions,
    #[command(flatten)]
    client: ClientArgs,
}

#[derive(Debug, Parser)]
#[command(author, version, about, hide = true)]
struct AgentCli {
    #[command(flatten)]
    global: GlobalOptions,
    #[command(flatten)]
    agent: AgentArgs,
}

#[derive(Debug, Clone, Args)]
pub struct ClientArgs {
    #[arg(short = 'L', value_name = "SPEC", action = ArgAction::Append)]
    local_forwards: Vec<String>,
    #[arg(short = 'R', value_name = "SPEC", action = ArgAction::Append)]
    remote_forwards: Vec<String>,
    #[arg(short = 'p')]
    pub port: Option<u16>,
    #[arg(short = 'i')]
    pub identity_file: Option<PathBuf>,
    #[arg(short = 'J')]
    pub proxy_jump: Option<String>,
    #[arg(short = 'o', action = ArgAction::Append)]
    pub ssh_options: Vec<String>,
    #[arg(short = 'F')]
    pub ssh_config: Option<PathBuf>,
    #[arg(short = 'l')]
    pub login_name: Option<String>,
    #[arg(short = '4', action = ArgAction::SetTrue)]
    pub ipv4: bool,
    #[arg(short = '6', action = ArgAction::SetTrue)]
    pub ipv6: bool,
    #[arg(short = 'N', action = ArgAction::SetTrue)]
    pub no_remote_command: bool,
    #[arg(long = "ssh-arg", action = ArgAction::Append)]
    pub ssh_args: Vec<String>,
    #[arg(long = "remote-path", default_value = "udpduct")]
    pub remote_path: String,
    #[arg(long = "udp-host")]
    pub udp_host: Option<String>,
    #[arg(long = "udp-port")]
    pub udp_port: Option<u16>,
    #[arg(long = "udp-port-range", value_parser = parse_port_range)]
    pub udp_port_range: Option<(u16, u16)>,
    #[arg(long = "keepalive", default_value = "15s", value_parser = parse_duration)]
    pub keepalive: Duration,
    #[arg(long = "idle-timeout", default_value = "60s", value_parser = parse_duration)]
    pub idle_timeout: Duration,
    #[arg(long = "max-dgram", default_value_t = 1200)]
    pub max_dgram: usize,
    #[arg(value_name = "DESTINATION")]
    pub destination: String,
}

#[derive(Debug, Clone, Args)]
pub struct AgentArgs {
    #[arg(long, action = ArgAction::SetTrue)]
    pub stdio: bool,
}

pub fn parse() -> Result<(GlobalOptions, Command)> {
    parse_from(std::env::args_os())
}

fn parse_from<I, T>(args: I) -> Result<(GlobalOptions, Command)>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let args: Vec<_> = args.into_iter().map(Into::into).collect();
    if args.get(1).map(|arg| arg.as_os_str()) == Some(std::ffi::OsStr::new("agent")) {
        let mut rewritten = Vec::with_capacity(args.len() - 1);
        rewritten.push(args[0].clone());
        rewritten.extend(args.iter().skip(2).cloned());
        let cli = AgentCli::parse_from(rewritten);
        Ok((cli.global, Command::Agent(cli.agent)))
    } else {
        let cli = ClientCli::parse_from(args);
        Ok((cli.global, Command::Client(Box::new(cli.client))))
    }
}

#[derive(Debug, Clone)]
pub struct ParsedClientArgs {
    pub ssh: SshArgs,
    pub forwards: Vec<ForwardSpec>,
    pub remote_path: String,
    pub udp_host: Option<String>,
    pub udp_port: Option<u16>,
    pub udp_port_range: Option<(u16, u16)>,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    pub max_dgram: usize,
    pub family: Option<IpFamily>,
}

#[derive(Debug, Clone)]
pub struct SshArgs {
    pub destination: String,
    pub port: Option<u16>,
    pub identity_file: Option<PathBuf>,
    pub proxy_jump: Option<String>,
    pub ssh_options: Vec<String>,
    pub ssh_config: Option<PathBuf>,
    pub login_name: Option<String>,
    pub extra_args: Vec<String>,
    pub quiet: bool,
    pub verbose: u8,
}

impl ClientArgs {
    pub fn parse(self, global: GlobalOptions) -> Result<ParsedClientArgs> {
        if self.local_forwards.is_empty() && self.remote_forwards.is_empty() {
            anyhow::bail!("at least one of -L or -R is required");
        }
        if self.ipv4 && self.ipv6 {
            anyhow::bail!("only one of -4 or -6 may be set");
        }
        if self.max_dgram < 64 {
            anyhow::bail!("--max-dgram must be at least 64 bytes");
        }
        let family = if self.ipv4 {
            Some(IpFamily::V4)
        } else if self.ipv6 {
            Some(IpFamily::V6)
        } else {
            None
        };

        let mut forwards = Vec::new();
        let mut rule_id = 1u32;
        for value in self.local_forwards {
            forwards.push(parse_forward_spec(&value, ListenSide::Local, rule_id)?);
            rule_id += 1;
        }
        for value in self.remote_forwards {
            forwards.push(parse_forward_spec(&value, ListenSide::Remote, rule_id)?);
            rule_id += 1;
        }

        Ok(ParsedClientArgs {
            ssh: SshArgs {
                destination: self.destination,
                port: self.port,
                identity_file: self.identity_file,
                proxy_jump: self.proxy_jump,
                ssh_options: self.ssh_options,
                ssh_config: self.ssh_config,
                login_name: self.login_name,
                extra_args: self.ssh_args,
                quiet: global.quiet,
                verbose: global.verbose,
            },
            forwards,
            remote_path: self.remote_path,
            udp_host: self.udp_host,
            udp_port: self.udp_port,
            udp_port_range: self.udp_port_range,
            keepalive: self.keepalive,
            idle_timeout: self.idle_timeout,
            max_dgram: self.max_dgram,
            family,
        })
    }
}

pub fn init_logging(global: &GlobalOptions) {
    let directive = if global.quiet {
        "warn"
    } else {
        match global.verbose {
            0 => "info",
            1 => "debug",
            _ => "trace",
        }
    };
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(directive))
        .unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .init();
}

fn parse_duration(input: &str) -> Result<Duration> {
    let input = input.trim();
    let (digits, unit) = input
        .chars()
        .position(|c| !c.is_ascii_digit())
        .map(|idx| input.split_at(idx))
        .unwrap_or((input, "s"));
    let value = digits
        .parse::<u64>()
        .with_context(|| format!("invalid duration `{input}`"))?;
    let duration = match unit {
        "ms" => Duration::from_millis(value),
        "s" | "" => Duration::from_secs(value),
        "m" => Duration::from_secs(value * 60),
        _ => anyhow::bail!("unsupported duration unit `{unit}`"),
    };
    Ok(duration)
}

fn parse_port_range(input: &str) -> Result<(u16, u16)> {
    let (start, end) = input
        .split_once(':')
        .with_context(|| format!("invalid port range `{input}`"))?;
    let start = start.parse::<u16>()?;
    let end = end.parse::<u16>()?;
    if start > end {
        anyhow::bail!("invalid port range `{input}`");
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::{Command, parse_duration, parse_from, parse_port_range};

    #[test]
    fn parses_durations() {
        assert_eq!(parse_duration("15s").unwrap().as_secs(), 15);
        assert_eq!(parse_duration("2m").unwrap().as_secs(), 120);
        assert_eq!(parse_duration("250ms").unwrap().as_millis(), 250);
    }

    #[test]
    fn parses_port_range() {
        assert_eq!(parse_port_range("4000:4010").unwrap(), (4000, 4010));
        assert!(parse_port_range("4010:4000").is_err());
    }

    #[test]
    fn parses_client_command_line() {
        let (_, command) = parse_from([
            "udpduct",
            "-vv",
            "-L",
            "0:127.0.0.1:53",
            "-R",
            "[::1]:0:[2001:db8::1]:5353",
            "-p",
            "2222",
            "--udp-host",
            "198.51.100.20",
            "user@example.com",
        ])
        .unwrap();

        let Command::Client(args) = command else {
            panic!("expected client command");
        };
        assert_eq!(args.destination, "user@example.com");
        assert_eq!(args.port, Some(2222));
        assert_eq!(args.udp_host.as_deref(), Some("198.51.100.20"));

        let parsed = args
            .parse(super::GlobalOptions {
                verbose: 2,
                quiet: false,
            })
            .unwrap();
        assert_eq!(parsed.forwards.len(), 2);
        assert_eq!(parsed.forwards[0].rule_id, 1);
        assert_eq!(parsed.forwards[1].rule_id, 2);
    }

    #[test]
    fn parses_hidden_agent_command_line() {
        let (_, command) = parse_from(["udpduct", "agent", "--stdio"]).unwrap();
        let Command::Agent(args) = command else {
            panic!("expected agent command");
        };
        assert!(args.stdio);
    }

    #[test]
    fn rejects_missing_forward_specs() {
        let (_, command) = parse_from(["udpduct", "example.com"]).unwrap();
        let Command::Client(args) = command else {
            panic!("expected client command");
        };
        let err = args
            .parse(super::GlobalOptions {
                verbose: 0,
                quiet: false,
            })
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("at least one of -L or -R is required")
        );
    }

    #[test]
    fn rejects_conflicting_ip_family_flags() {
        let (_, command) =
            parse_from(["udpduct", "-4", "-6", "-L", "0:127.0.0.1:53", "example.com"]).unwrap();
        let Command::Client(args) = command else {
            panic!("expected client command");
        };
        let err = args
            .parse(super::GlobalOptions {
                verbose: 0,
                quiet: false,
            })
            .unwrap_err();
        assert!(err.to_string().contains("only one of -4 or -6"));
    }
}
