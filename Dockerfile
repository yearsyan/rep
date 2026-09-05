# syntax=docker/dockerfile:1

# ---- 构建阶段 ----
# edition 2024 需要 Rust 1.85+,rust:1 始终是最新稳定版
FROM rust:1-slim-bookworm AS builder
WORKDIR /build

# 先只拷贝依赖清单并用空 main 预编译依赖,利用镜像层缓存
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs \
 && cargo build --release --locked \
 && rm -rf src target/release/rep

COPY src ./src
RUN cargo build --release --locked \
 && cp target/release/rep /usr/local/bin/rep

# ---- 运行阶段 ----
FROM debian:bookworm-slim AS runtime

# ca-certificates 非必需(隧道证书由用户挂载),但保留以备容器内诊断工具使用
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 1000 --no-create-home --shell /usr/sbin/nologin rep

COPY --from=builder /usr/local/bin/rep /usr/local/bin/rep

# 配置与证书挂载到 /config,配置内的相对路径按配置文件所在目录解析
WORKDIR /config
USER rep

# 服务端默认端口:tunnel 7000 / proxy 8080(仅声明,实际以配置为准)
EXPOSE 7000 8080

ENTRYPOINT ["/usr/local/bin/rep"]
CMD ["--help"]
