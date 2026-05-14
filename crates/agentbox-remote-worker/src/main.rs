use std::net::SocketAddr;

use agentbox_remote_worker::{serve, signing_key_from_hex_seed, RemoteWorkerConfig};

#[tokio::main]
async fn main() {
    let options = Options::parse_or_exit();
    let signing_key = signing_key_from_hex_seed(&options.signing_key_hex).unwrap_or_else(|err| {
        eprintln!("error: invalid --signing-key-hex: {err}");
        std::process::exit(2);
    });
    let config = RemoteWorkerConfig::new(
        options.worker_identity,
        options.evidence_endpoint,
        signing_key,
    );
    if let Err(err) = serve(options.listen, config).await {
        eprintln!("error: remote worker failed: {err}");
        std::process::exit(1);
    }
}

struct Options {
    listen: SocketAddr,
    worker_identity: String,
    evidence_endpoint: String,
    signing_key_hex: String,
}

impl Options {
    fn parse_or_exit() -> Self {
        let mut listen = "127.0.0.1:8787".parse().unwrap();
        let mut worker_identity = "worker.local/dev".to_string();
        let mut evidence_endpoint = "https://worker.example.com/agentpod/evidence".to_string();
        let mut signing_key_hex = None;
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => {
                    let value = next_value(&mut args, "--listen");
                    listen = value.parse().unwrap_or_else(|err| {
                        eprintln!("error: invalid --listen: {err}");
                        std::process::exit(2);
                    });
                }
                "--worker" => {
                    worker_identity = next_value(&mut args, "--worker");
                }
                "--evidence-endpoint" => {
                    evidence_endpoint = next_value(&mut args, "--evidence-endpoint");
                }
                "--signing-key-hex" => {
                    signing_key_hex = Some(next_value(&mut args, "--signing-key-hex"));
                }
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                unknown => {
                    eprintln!("error: unknown option {unknown}");
                    print_help();
                    std::process::exit(2);
                }
            }
        }
        let Some(signing_key_hex) = signing_key_hex else {
            eprintln!("error: --signing-key-hex is required");
            print_help();
            std::process::exit(2);
        };
        Self {
            listen,
            worker_identity,
            evidence_endpoint,
            signing_key_hex,
        }
    }
}

fn next_value(args: &mut impl Iterator<Item = String>, flag: &str) -> String {
    args.next().unwrap_or_else(|| {
        eprintln!("error: {flag} requires a value");
        std::process::exit(2);
    })
}

fn print_help() {
    eprintln!(
        "usage: agentbox-remote-worker --signing-key-hex <64-hex-seed> [--listen 127.0.0.1:8787] [--worker worker.local/dev] [--evidence-endpoint https://worker.example.com/agentpod/evidence]"
    );
}
