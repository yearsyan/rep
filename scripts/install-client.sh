#!/usr/bin/env bash
# rep 客户端一键安装脚本
# 从 GitHub Release 拉取 Linux 静态二进制,交互式收集服务端地址与证书,
# 写入 /etc/rep/client.toml 并安装 systemd 服务。
#
# 用法:
#   curl -fsSL https://raw.githubusercontent.com/yearsyan/rep/main/scripts/install-client.sh | sudo bash
#   curl -fsSL ... -o install-client.sh && sudo bash install-client.sh [版本tag]   # 默认 latest
set -euo pipefail

REPO="yearsyan/rep"
BIN_DIR="/usr/local/bin"
CONF_DIR="/etc/rep"
CERT_DIR="/etc/rep/certs"
SERVICE="rep-client"

say() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m警告:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m错误:\033[0m %s\n' "$*" >&2; exit 1; }

# 支持 curl | bash:交互输入改从终端读取
if [ ! -t 0 ]; then
  exec 0< /dev/tty || die "无终端可用,请先下载脚本后执行: sudo bash install-client.sh"
fi

[ "$(id -u)" -eq 0 ] || die "请用 root 运行(sudo bash $0)"

command -v curl >/dev/null || die "缺少 curl"
command -v tar >/dev/null || die "缺少 tar"
command -v sha256sum >/dev/null || die "缺少 sha256sum"

case "$(uname -sm)" in
  "Linux x86_64")  ARCH=amd64 ;;
  "Linux aarch64"|"Linux arm64") ARCH=arm64 ;;
  *) die "仅支持 Linux x86_64/aarch64,当前: $(uname -sm)" ;;
esac

# ---------- 1. 下载二进制 ----------
TAG="${1:-latest}"
if [ "$TAG" = "latest" ]; then
  say "查询最新版本..."
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -1)"
  [ -n "$TAG" ] || die "获取最新版本失败,请手动指定版本tag运行: bash $0 v0.1.0"
fi

PKG="rep-${TAG}-linux-${ARCH}.tar.gz"
BASE="https://github.com/${REPO}/releases/download/${TAG}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "下载 ${PKG}..."
curl -fSL --progress-bar -o "$TMP/$PKG" "$BASE/$PKG"
curl -fsSL -o "$TMP/$PKG.sha256" "$BASE/$PKG.sha256"

say "校验 sha256..."
(cd "$TMP" && sha256sum -c "$PKG.sha256" >/dev/null) || die "校验失败,文件可能损坏"

tar -xzf "$TMP/$PKG" -C "$TMP"
install -m 755 "$TMP/rep" "${BIN_DIR}/rep"
say "已安装 ${BIN_DIR}/rep ($(${BIN_DIR}/rep --version 2>/dev/null || echo "$TAG"))"

# ---------- 2. 收集配置 ----------
mkdir -p "$CERT_DIR"

printf '\n—— 服务端信息 ——\n'
read -r -p "服务端地址 (域名或 IP,可带端口,默认端口 7000): " SERVER_ADDR
[ -n "$SERVER_ADDR" ] || die "服务端地址不能为空"
# 容错:剥掉误粘贴的 scheme
SERVER_ADDR="${SERVER_ADDR#*://}"
case "$SERVER_ADDR" in
  *:*) ;;          # 已含端口
  \[*\]) SERVER_ADDR="${SERVER_ADDR}:7000" ;;   # 裸 IPv6
  *) SERVER_ADDR="${SERVER_ADDR}:7000" ;;
esac
SERVER_NAME="${SERVER_ADDR%%:*}"                 # 去端口作为默认 SNI
SERVER_NAME="${SERVER_NAME#[}"                   # 去 IPv6 括号
read -r -p "证书校验名/SNI [${SERVER_NAME}]: " INPUT_SNI
[ -n "$INPUT_SNI" ] && SERVER_NAME="$INPUT_SNI"

# 读取 PEM:优先给文件路径,留空则粘贴内容(Ctrl-D 结束)
read_pem() {
  local label="$1" out="$2" marker="$3" path
  while :; do
    printf '\n—— %s ——\n' "$label"
    read -r -p "文件路径 (留空则直接粘贴内容): " path
    if [ -n "$path" ]; then
      [ -f "$path" ] || { warn "文件不存在: $path"; continue; }
      cp "$path" "$out"
    else
      printf '粘贴 PEM 内容,完成后另起一行按 Ctrl-D:\n'
      cat > "$out"
    fi
    grep -q "$marker" "$out" && return 0
    warn "内容缺少 ${marker},不是有效的 ${label},请重试"
  done
}

read_pem "CA 证书 (ca.pem)"        "$CERT_DIR/ca.pem"     "BEGIN CERTIFICATE"
read_pem "客户端证书 (client.pem)" "$CERT_DIR/client.pem" "BEGIN CERTIFICATE"
read_pem "客户端私钥 (client.key)" "$CERT_DIR/client.key" "PRIVATE KEY"

chmod 644 "$CERT_DIR/ca.pem" "$CERT_DIR/client.pem"
chmod 600 "$CERT_DIR/client.key"

# 有 openssl 时校验证书与私钥、CA 的配对关系
if command -v openssl >/dev/null; then
  cert_pub="$(openssl x509 -in "$CERT_DIR/client.pem" -pubkey -noout 2>/dev/null | sha256sum | cut -d' ' -f1)" \
    || die "client.pem 无法解析"
  key_pub="$(openssl pkey -in "$CERT_DIR/client.key" -pubout 2>/dev/null | sha256sum | cut -d' ' -f1)" \
    || die "client.key 无法解析"
  [ "$cert_pub" = "$key_pub" ] || die "client.pem 与 client.key 不匹配"
  # RFC2253 让不同 openssl 版本的输出格式一致
  issuer="$(openssl x509 -in "$CERT_DIR/client.pem" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')"
  subject="$(openssl x509 -in "$CERT_DIR/ca.pem" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')"
  [ "$issuer" = "$subject" ] \
    || warn "client.pem 的签发者与 ca.pem 主体不一致,请确认是同一套证书(仍继续安装)"
  say "证书配对校验通过"
else
  warn "未安装 openssl,跳过证书配对校验"
fi

# ---------- 3. 写配置 ----------
cat > "$CONF_DIR/client.toml" <<EOF
server_addr = "${SERVER_ADDR}"
server_name = "${SERVER_NAME}"
ca = "certs/ca.pem"
cert = "certs/client.pem"
key = "certs/client.key"

ipv6_probe_timeout_secs = 3
ipv6_probe_addrs = [
  "[2606:4700:4700::1111]:443",
  "[2001:4860:4860::8888]:443",
]

[retry]
target_attempts = 3
connect_timeout_secs = 10
keepalive_secs = 15
reconnect_initial_ms = 1000
reconnect_max_ms = 30000
EOF

# ---------- 4. systemd 服务 ----------
if command -v systemctl >/dev/null; then
  cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=rep reverse-tunnel client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${BIN_DIR}/rep client --config ${CONF_DIR}/client.toml
Environment=RUST_LOG=info
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now "$SERVICE"
  say "安装完成,服务已启动:"
  printf '  查看状态: systemctl status %s\n' "$SERVICE"
  printf '  查看日志: journalctl -u %s -f\n' "$SERVICE"
else
  say "未检测到 systemd,手动运行:"
  printf '  rep client --config %s/client.toml\n' "$CONF_DIR"
fi

say "完成。配置: ${CONF_DIR}/client.toml,证书: ${CERT_DIR}/"
