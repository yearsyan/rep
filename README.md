# rep — HTTP/2 反向隧道代理

无公网 IP 的客户端（A）借公网服务端（B）暴露一个 HTTP/HTTPS 代理：通过 B 的本机/内网代理端口，流量经隧道从 A 的网络出口访问目标。

```
用户/浏览器 ──HTTP代理──▶ B: proxy_port (rep server, 本机/内网)
                          │  mTLS + HTTP/2（单条长连接，流级多路复用）
                          ▼
                        A (rep client, 内网)
                          │ 每通道独立解析 DNS 并连接目标（可自动重试）
                          ▼
                       目标网站（出口 IP 为 A）
```

## 特性

- **mTLS 鉴权**：自建 CA 一键签发；B 只接受该 CA 签发的客户端证书，A 固定同一 CA 校验服务端，应用层无需密码
- **HTTP/2 多路复用**：所有代理通道复用一条 TLS 长连接上的 h2 stream，双向流控
- **自动重连**：断线后指数退避重连（默认 1s→30s 带抖动），h2 PING 保活检测半开连接
- **目标连接重试**：每次尝试重新 DNS 解析，目标机器地址变化可被感知；失败默认重试 3 次后向用户回 502
- **HTTP 代理完整语义**：支持 CONNECT（HTTPS）与 absolute-form（HTTP）请求
- **本机/内网代理**：代理端口无需鉴权；可用 `proxy.tls = true` 启用代理端口 TLS

## 快速开始

```bash
# 在 B（公网机器）上初始化：生成 CA、证书、server.toml、client.toml
rep cert init your.domain.com --out .
# 如需按 IP 访问，追加 SAN：
rep cert init your.domain.com --ip 1.2.3.4 --out .

# B 上运行服务端
rep server --config server.toml

# 把 client.toml 和 certs/{ca,client}.pem/key 拷到 A，运行客户端
rep client --config client.toml

# 在 B 本机使用代理
curl -x http://127.0.0.1:8080 https://example.com
```

追加客户端证书：

```bash
rep cert issue-client --name laptop --config server.toml
# 生成 certs/laptop.pem 与 certs/laptop.key，client.toml 指向它们即可
```

注意：**没有吊销机制**。服务端只校验"证书是否由该 CA 签发"，删除或重签磁盘上的证书文件不会使已签发的证书失效；要踢掉某个客户端，只能轮换 CA（重新 `cert init --force` 并分发新证书）。叶证书有效期默认 3 年、CA 10 年。

## 配置

**server.toml**（端口均可改；证书相对路径按配置文件所在目录解析）：

```toml
[tunnel]
listen = "0.0.0.0:7000"        # 接受 A 接入的 mTLS+h2 端口

[tunnel.tls]
ca = "certs/ca.pem"            # 信任的客户端 CA
cert = "certs/server.pem"      # 服务端证书（隧道与代理 TLS 共用）
key = "certs/server.key"

[proxy]
listen = "127.0.0.1:8080"      # 代理端口；默认仅本机，内网使用时填写对应监听地址
tls = false                    # true 则代理端口走 TLS（用户侧无需客户端证书）
max_connections = 256          # 最大并发用户连接，超出立即回 503
```

**client.toml**：

```toml
server_addr = "your.domain.com:7000"
server_name = "your.domain.com"   # SNI 与证书校验名
ca = "certs/ca.pem"
cert = "certs/client.pem"
key = "certs/client.key"

# IPv6 真实连通性在后台探测，不会阻塞 TCP/TLS/H2 握手；
# 不可用或尚未完成时优先尝试 DNS 返回的 IPv4 地址，但不会过滤任何目标
ipv6_probe_timeout_secs = 3
ipv6_probe_addrs = [
  "[2606:4700:4700::1111]:443",
  "[2001:4860:4860::8888]:443",
]

[retry]
target_attempts = 3          # 目标连接重试次数（每次重新解析 DNS）
connect_timeout_secs = 10    # 每轮 DNS + 所有目标地址连接的总超时
keepalive_secs = 15          # h2 PING 间隔（2 倍超时判死）
reconnect_initial_ms = 1000  # 重连退避起点
reconnect_max_ms = 30000     # 重连退避上限
```

## 行为细节

- 普通 HTTP 请求会按 URL 的 authority 重建 Host、改写为 origin-form 并加 `Connection: close`，每条代理连接只转发一个请求及其完整请求体（按 Content-Length 或 chunked 边界流式处理，无 Content-Length 和 Transfer-Encoding 则请求体为空），后续请求丢弃，响应完成后关闭连接；HTTPS 走 CONNECT 隧道，双向透传（与 CONNECT 头同包到达的早期隧道数据会被保留转发）
- IPv6 目标完整支持（`[::1]`、`[2001:db8::1]` 等形式均可）；客户端在后台做 TCP 探测，不阻塞隧道握手，仅用结果调整 DNS 多地址时的尝试顺序；多地址连接每隔 250ms 错峰发起，失败时立即尝试下一个地址，避免首个地址无响应阻塞回退
- 通道建立：用户请求 → B 在 h2 控制流上发 `ChannelOpen` → A 开新 h2 stream 连接目标并回报结果 → 成功桥接 / 失败回 502
- 会话生命周期：客户端的 TCP（含 DNS）、TLS、H2 和控制流响应共用 15 秒建立期限；建立失败或会话断开时，取消连接驱动、PING、控制流读写、探测和所有目标通道任务，等待清理后重连；新客户端接入会替换旧会话
- 资源上限：代理侧 `max_connections`（默认 256）、服务端挂起通道 1024、客户端并发通道 128；TLS/h2 握手最多并发 16 个，满载连接立即断开、不在进程内排队；挂起通道由会话级定时队列统一回收
- 多个客户端同时接入时，服务端只保留最新会话（旧连接被替换）
- 日志级别用 `RUST_LOG` 控制（默认 info）

## 安全须知

- **无吊销机制**：踢掉客户端只能轮换 CA（见上文）
- **代理权限**：代理端口不鉴权，面向本机/内网使用；目标地址不做范围限制，使用客户端的网络出口访问目标

## 限制

- 代理端口仅支持 HTTP/1.1（curl、浏览器代理场景足够）
- 单 TCP 上 h2 存在队头阻塞，弱网高延迟场景可考虑未来迁移 QUIC

## 构建

```bash
cargo build --release
```

## 回归测试

```sh
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo build --locked
python3.14 tests/tls_certificates.py
python3 tests/http_proxy.py
```

Rust 测试和 HTTP 端到端测试包含本机回环端口连接，需要允许监听本地端口。HTTP 测试覆盖连续请求隔离、Content-Length/chunked 上传、100 Continue 和 CONNECT。TLS 测试使用 Python 标准库、临时证书和内存 BIO，不监听端口；要求 Python 3.13+ 的默认严格校验。

新生成的服务端和客户端叶证书均包含 Authority Key Identifier（含 `cert issue-client`）。已有叶证书需重新签发才能获得此扩展。
