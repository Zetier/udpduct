use std::ffi::OsString;
use std::process::Stdio;

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStderr, ChildStdin, Command};
use tracing::{debug, warn};

use crate::cli::SshArgs;
use crate::protocol::{BootstrapReply, BootstrapRequest, decode_line, encode_line};

pub struct RemoteAgentProcess {
    child: Child,
    _stdin: ChildStdin,
}

impl RemoteAgentProcess {
    pub async fn start(
        ssh: &SshArgs,
        remote_path: &str,
        request: &BootstrapRequest,
    ) -> Result<(Self, BootstrapReply)> {
        let mut command = Command::new("ssh");
        command.args(build_ssh_args(ssh, remote_path));
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());

        debug!("starting ssh bootstrap process");
        let mut child = command.spawn().context("failed to spawn ssh")?;
        let mut stdin = child.stdin.take().context("missing ssh stdin")?;
        let stdout = child.stdout.take().context("missing ssh stdout")?;
        let stderr = child.stderr.take().context("missing ssh stderr")?;
        spawn_stderr_task(stderr);

        stdin.write_all(&encode_line(request)?).await?;
        stdin.flush().await?;

        let mut stdout = BufReader::new(stdout);
        let mut line = Vec::new();
        let count = stdout.read_until(b'\n', &mut line).await?;
        if count == 0 {
            let status = child.wait().await.context("ssh exited before replying")?;
            bail!("ssh bootstrap failed with status {status}");
        }
        let reply: BootstrapReply = decode_line(&line)?;
        if let Some(error) = &reply.error {
            bail!("{error}");
        }

        Ok((
            Self {
                child,
                _stdin: stdin,
            },
            reply,
        ))
    }

    pub async fn wait(mut self) -> Result<()> {
        let status = self.child.wait().await?;
        if status.success() {
            Ok(())
        } else {
            bail!("ssh process exited with status {status}")
        }
    }
}

fn build_ssh_args(ssh: &SshArgs, remote_path: &str) -> Vec<OsString> {
    let mut args = Vec::new();
    args.push(OsString::from("-T"));
    if ssh.quiet {
        args.push(OsString::from("-q"));
    }
    for _ in 0..ssh.verbose {
        args.push(OsString::from("-v"));
    }
    if let Some(port) = ssh.port {
        args.push(OsString::from("-p"));
        args.push(OsString::from(port.to_string()));
    }
    if let Some(identity_file) = &ssh.identity_file {
        args.push(OsString::from("-i"));
        args.push(identity_file.clone().into_os_string());
    }
    if let Some(proxy_jump) = &ssh.proxy_jump {
        args.push(OsString::from("-J"));
        args.push(OsString::from(proxy_jump));
    }
    for option in &ssh.ssh_options {
        args.push(OsString::from("-o"));
        args.push(OsString::from(option));
    }
    if let Some(config) = &ssh.ssh_config {
        args.push(OsString::from("-F"));
        args.push(config.clone().into_os_string());
    }
    if let Some(login_name) = &ssh.login_name {
        args.push(OsString::from("-l"));
        args.push(OsString::from(login_name));
    }
    for arg in &ssh.extra_args {
        args.push(OsString::from(arg));
    }
    args.push(OsString::from(&ssh.destination));
    args.push(OsString::from(format!(
        "{} agent --stdio",
        shell_quote(remote_path)
    )));
    args
}

fn shell_quote(input: &str) -> String {
    let escaped = input.replace('\'', "'\"'\"'");
    format!("'{escaped}'")
}

fn spawn_stderr_task(stderr: ChildStderr) {
    tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => warn!("ssh: {line}"),
                Ok(None) => break,
                Err(err) => {
                    warn!("error reading ssh stderr: {err}");
                    break;
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{build_ssh_args, shell_quote};
    use crate::cli::SshArgs;

    #[test]
    fn shell_quote_escapes_single_quotes() {
        assert_eq!(shell_quote("udpduct"), "'udpduct'");
        assert_eq!(shell_quote("a'b"), "'a'\"'\"'b'");
    }

    #[test]
    fn builds_expected_ssh_arguments() {
        let ssh = SshArgs {
            destination: "user@example.com".to_string(),
            port: Some(2222),
            identity_file: Some(PathBuf::from("/tmp/id_ed25519")),
            proxy_jump: Some("jumpbox".to_string()),
            ssh_options: vec!["StrictHostKeyChecking=no".to_string()],
            ssh_config: Some(PathBuf::from("/tmp/ssh_config")),
            login_name: Some("other-user".to_string()),
            extra_args: vec!["--".to_string()],
            quiet: true,
            verbose: 2,
        };

        let args = build_ssh_args(&ssh, "/opt/udpduct/bin/udpduct");
        let args: Vec<String> = args
            .into_iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();

        assert_eq!(args[0], "-T");
        assert!(args.contains(&"-q".to_string()));
        assert_eq!(args.iter().filter(|arg| arg.as_str() == "-v").count(), 2);
        assert!(args.windows(2).any(|w| w == ["-p", "2222"]));
        assert!(args.windows(2).any(|w| w == ["-i", "/tmp/id_ed25519"]));
        assert!(args.windows(2).any(|w| w == ["-J", "jumpbox"]));
        assert!(
            args.windows(2)
                .any(|w| w == ["-o", "StrictHostKeyChecking=no"])
        );
        assert!(args.windows(2).any(|w| w == ["-F", "/tmp/ssh_config"]));
        assert!(args.windows(2).any(|w| w == ["-l", "other-user"]));
        assert_eq!(args[args.len() - 2], "user@example.com");
        assert_eq!(
            args.last().unwrap(),
            "'/opt/udpduct/bin/udpduct' agent --stdio"
        );
    }
}
