use std::env;
use std::net::SocketAddr;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::UdpSocket;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

#[tokio::test]
async fn ssh_localhost_forwards_local_and_remote_udp() {
    if env::var_os("UDPDUCT_TEST_SSH_LOCALHOST").is_none() {
        return;
    }

    let destination =
        env::var("UDPDUCT_TEST_SSH_DESTINATION").unwrap_or_else(|_| "localhost".to_string());
    let binary = env::var("CARGO_BIN_EXE_udpduct").expect("missing udpduct binary path");

    let (remote_target_addr, remote_target_task) = spawn_udp_echo_server().await;
    let (local_target_addr, local_target_task) = spawn_udp_echo_server().await;
    let local_forward_port = reserve_port().await;
    let remote_forward_port = reserve_port().await;

    let mut child = Command::new(&binary)
        .arg("-q")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("StrictHostKeyChecking=no")
        .arg("-o")
        .arg("UserKnownHostsFile=/dev/null")
        .arg("-o")
        .arg("ConnectTimeout=5")
        .arg("--remote-path")
        .arg(&binary)
        .arg("--keepalive")
        .arg("1s")
        .arg("--idle-timeout")
        .arg("10s")
        .arg(&destination)
        .arg("-L")
        .arg(format!(
            "{local_forward_port}:127.0.0.1:{}",
            remote_target_addr.port()
        ))
        .arg("-R")
        .arg(format!(
            "{remote_forward_port}:127.0.0.1:{}",
            local_target_addr.port()
        ))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("failed to spawn udpduct");

    let stdout = child.stdout.take().expect("missing stdout");
    let stderr = child.stderr.take().expect("missing stderr");
    let stderr_task = tokio::spawn(async move {
        let mut reader = BufReader::new(stderr).lines();
        let mut lines = Vec::new();
        while let Ok(Some(line)) = reader.next_line().await {
            lines.push(line);
        }
        lines
    });

    let mut stdout_reader = BufReader::new(stdout).lines();
    let startup = timeout(Duration::from_secs(10), async {
        let mut lines = Vec::new();
        while lines.len() < 2 {
            let line = stdout_reader
                .next_line()
                .await
                .expect("failed to read startup output")
                .expect("udpduct exited before reporting startup");
            if line.contains(" -> ") {
                lines.push(line);
            }
        }
        lines
    })
    .await
    .expect("timed out waiting for udpduct startup output");

    assert!(startup.iter().any(|line| line.starts_with("local ")));
    assert!(startup.iter().any(|line| line.starts_with("remote ")));

    sleep(Duration::from_millis(100)).await;

    let local_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    local_client
        .send_to(
            b"localhost-ssh-local",
            SocketAddr::from(([127, 0, 0, 1], local_forward_port)),
        )
        .await
        .unwrap();
    let mut buffer = [0u8; 256];
    let size = timeout(Duration::from_secs(3), local_client.recv(&mut buffer))
        .await
        .expect("timed out waiting for local forward reply")
        .unwrap();
    assert_eq!(&buffer[..size], b"localhost-ssh-local");

    let remote_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    remote_client
        .send_to(
            b"localhost-ssh-remote",
            SocketAddr::from(([127, 0, 0, 1], remote_forward_port)),
        )
        .await
        .unwrap();
    let size = timeout(Duration::from_secs(3), remote_client.recv(&mut buffer))
        .await
        .expect("timed out waiting for remote forward reply")
        .unwrap();
    assert_eq!(&buffer[..size], b"localhost-ssh-remote");

    terminate_child(&mut child).await;
    remote_target_task.abort();
    local_target_task.abort();

    let stderr_lines = stderr_task.await.unwrap();
    if let Some(status) = child.try_wait().unwrap() {
        assert!(
            status.success(),
            "udpduct exited unsuccessfully after test: status={status}, stderr={stderr_lines:?}"
        );
    }
}

async fn reserve_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn spawn_udp_echo_server() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0u8; 2048];
        loop {
            let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..size], peer).await.unwrap();
        }
    });
    (addr, task)
}

async fn terminate_child(child: &mut Child) {
    let _ = child.kill().await;
    let _ = child.wait().await;
}
