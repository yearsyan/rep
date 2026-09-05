# rep — HTTP/2 反向隧道代理

无公网 IP 的客户端（A）借公网服务端（B）暴露一个 HTTP/HTTPS 代理：通过 B 的本机/内网代理端口，流量经隧道从 A 的网络出口访问目标。

支持多个隧道客户端同时在线，每个客户端独立绑定一个 HTTP 代理端口。服务端先校验 mTLS 证书，再用客户端叶证书的 CN 匹配 `client_name`；名称区分大小写，不接受客户端自行上报身份。只有配置过的身份才能接入。

### 多客户端配置

先生成 CA、服务端证书和默认客户端证书，再按名称签发其他客户端证书：

```sh
rep cert init proxy.example.com
rep cert issue-client --name office-b --config server.toml
```

初始 `certs/client.pem` 的 CN 是 `rep-client`；追加签发的 `certs/office-b.pem` 的 CN 是 `office-b`。在服务端的 `server.toml` 中配置：

```toml
[tunnel]
listen = "0.0.0.0:7000"

[tunnel.tls]
ca = "certs/ca.pem"
cert = "certs/server.pem"
key = "certs/server.key"

[[proxies]]
client_name = "rep-client"
listen = "127.0.0.1:8080"
tls = false
max_connections = 256

[[proxies]]
client_name = "office-b"
listen = "127.0.0.1:8081"
tls = false
max_connections = 256
```

第一个客户端使用生成的 `client.toml`。第二个客户端使用如下配置，并持有自己的证书、私钥和公共 CA 证书（无需 CA 私钥）：

```toml
server_addr = "proxy.example.com:7000"
server_name = "proxy.example.com"
ca = "certs/ca.pem"
cert = "certs/office-b.pem"
key = "certs/office-b.key"
```

分别运行 `rep server --config server.toml` 和各机器上的 `rep client --config client.toml`。在服务端上使用代理：

```sh
curl --proxy http://127.0.0.1:8080 https://example.com
curl --proxy http://127.0.0.1:8081 https://example.com
```

8080 通过 `rep-client` 的网络出口，8081 通过 `office-b` 的网络出口。每个端口有独立的并发限制；客户端离线时对应端口返回 502，不会转发到其他客户端。同一 CN 的新会话会关闭旧会话，因此不同机器应使用不同名称的证书；同名证书续签后仍匹配原端口。修改端口映射后需重启服务端。

旧的 `[proxy]` 单端口配置仍可用，省略 `client_name` 时绑定 `rep-client`；以前使用追加签发证书的部署需把其 CN 填入 `client_name`。`[proxy]` 与 `[[proxies]]` 不能混用，重复名称和重复监听地址会报错。未配置代理时默认使用 `rep-client` / `127.0.0.1:8080`。

代理端口的 `tls = true` 使用服务端证书提供 HTTPS 代理；代理使用者无需客户端证书。客户端身份验证发生在隧道端口。

### 验证

```sh
cargo test --locked
cargo build --locked
python3 tests/http_proxy.py
python3 tests/multi_client.py
python3.14 tests/tls_certificates.py
```
