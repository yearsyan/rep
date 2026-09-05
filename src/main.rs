mod cert;
mod client;
mod config;
mod proto;
mod server;
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "rep",
    about = "HTTP/2 反向隧道代理：无公网客户端借公网服务端暴露 HTTP 代理出口"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 证书签发
    Cert {
        #[command(subcommand)]
        cmd: CertCommand,
    },
    /// 运行服务端（公网侧）
    Server {
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
    },
    /// 运行客户端（内网侧）
    Client {
        #[arg(short, long, default_value = "client.toml")]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum CertCommand {
    /// 初始化 CA 并签发服务端/客户端证书，生成 server.toml 与 client.toml
    Init {
        /// 服务端域名（写入证书 SAN 与 client.toml）
        #[arg(default_value = "localhost")]
        domain: String,
        /// 额外写入服务端证书 SAN 的 IP，可多次指定
        #[arg(long = "ip")]
        ips: Vec<String>,
        /// 输出目录
        #[arg(short, long, default_value = ".")]
        out: PathBuf,
        /// 覆盖已存在的证书与配置
        #[arg(long)]
        force: bool,
    },
    /// 用已有 CA 追加签发客户端证书
    IssueClient {
        #[arg(short, long)]
        name: String,
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
        /// 覆盖已存在的同名证书
        #[arg(long)]
        force: bool,
    },
}

fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.command {
        Command::Cert { cmd } => match cmd {
            CertCommand::Init {
                domain,
                ips,
                out,
                force,
            } => cert::run_init(&domain, &ips, &out, force),
            CertCommand::IssueClient { name, config, force } => {
                cert::run_issue_client(&name, &config, force)
            }
        },
        Command::Server { config } => {
            let cfg = config::load_server_config(&config)?;
            tokio::runtime::Runtime::new()?.block_on(server::run(cfg))
        }
        Command::Client { config } => {
            let cfg = config::load_client_config(&config)?;
            tokio::runtime::Runtime::new()?.block_on(client::run(cfg))
        }
    }
}
