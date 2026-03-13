#[tokio::main]
async fn main() {
    if let Err(err) = udpduct::run().await {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}
