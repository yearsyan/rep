mod cert;
mod client;
mod config;
mod embed;
mod proto;
mod server;
mod tls;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    name = "rep",
    version,
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
    /// 生成内嵌配置的客户端可执行文件(单文件、零参数接入)
    Embed {
        #[command(subcommand)]
        cmd: EmbedCommand,
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

#[derive(Subcommand)]
enum EmbedCommand {
    /// 签发证书、注册到服务端配置,并生成自包含的客户端可执行文件
    Create {
        /// 客户端名称(缺省交互输入)
        name: Option<String>,
        #[arg(short, long, default_value = "server.toml")]
        config: PathBuf,
        /// 目标架构:amd64/x86_64、aarch64/arm64;缺省与当前二进制相同
        #[arg(short, long)]
        arch: Option<String>,
        /// 客户端连接的服务端地址 host:port;缺省读同目录 client.toml,再缺省交互输入
        #[arg(long)]
        server_addr: Option<String>,
        /// 该客户端在服务端的代理监听地址;缺省自动取下一个端口
        #[arg(long)]
        listen: Option<String>,
        /// 输出文件路径;缺省 ./rep-client-<名称>
        #[arg(short, long)]
        out: Option<PathBuf>,
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

    // 无参数启动:若自身携带内嵌配置,直接作为客户端运行
    if std::env::args().len() == 1 && let Some(text) = embed::embedded_config_of_current_exe() {
        let cfg = config::parse_client_config(&text)?;
        info!(server = %cfg.server_addr, "启动内嵌客户端");
        return tokio::runtime::Runtime::new()?.block_on(client::run(cfg));
    }

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
        Command::Embed { cmd } => match cmd {
            EmbedCommand::Create {
                name,
                config,
                arch,
                server_addr,
                listen,
                out,
                force,
            } => embed::run_create(embed::CreateArgs {
                name,
                config,
                arch,
                server_addr,
                listen,
                out,
                force,
            }),
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
