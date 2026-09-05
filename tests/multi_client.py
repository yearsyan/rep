"""Multi-client mTLS routing: cargo build --locked && python3 tests/multi_client.py.

Uses temporary certificates, local processes and loopback sockets only.
"""

from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
REP = Path(os.environ.get("REP_BIN", ROOT / "target/debug/rep"))


def wait_for(check, message):
    deadline = time.monotonic() + 10
    while not check():
        if time.monotonic() >= deadline:
            raise AssertionError(message)
        time.sleep(0.05)


def read_until(sock, marker):
    data = b""
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.path.encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


class MultiClientTests(unittest.TestCase):
    def test_routing_replacement_and_authorization(self):
        with tempfile.TemporaryDirectory(prefix="rep-multi-") as temp, ExitStack() as stack:
            directory = Path(temp)
            processes = []

            def stop(process):
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=3)

            def start(role, label, config):
                path = directory / f"{label}.toml"
                path.write_text(config)
                log = directory / f"{label}.log"
                output = stack.enter_context(log.open("w"))
                process = subprocess.Popen(
                    [REP, role, "--config", path], stdout=output, stderr=subprocess.STDOUT,
                    env={**os.environ, "RUST_LOG": "info", "NO_COLOR": "1"},
                )
                processes.append(process)
                stack.callback(stop, process)
                return process, log

            # Reserve ports together to prevent accidental duplicate allocation.
            reservations = []
            for _ in range(3):
                sock = stack.enter_context(socket.socket())
                sock.bind(("127.0.0.1", 0))
                reservations.append(sock)
            tunnel_port, a_port, b_port = [s.getsockname()[1] for s in reservations]
            subprocess.run([REP, "cert", "init", "localhost", "--out", directory],
                           check=True, capture_output=True)
            for name in ["a", "b", "unknown"]:
                subprocess.run([REP, "cert", "issue-client", "--name", name,
                                "--config", directory / "server.toml"],
                               check=True, capture_output=True)
            for sock in reservations:
                sock.close()
            _, server_log = start("server", "server", f"""
[tunnel]
listen = "127.0.0.1:{tunnel_port}"
[[proxies]]
client_name = "a"
listen = "127.0.0.1:{a_port}"
max_connections = 1
[[proxies]]
client_name = "b"
listen = "127.0.0.1:{b_port}"
max_connections = 2
""")

            def client_config(name, cert_dir="certs"):
                return f"""
server_addr = "127.0.0.1:{tunnel_port}"
server_name = "localhost"
ca = "certs/ca.pem"
cert = "{cert_dir}/{name}.pem"
key = "{cert_dir}/{name}.key"
ipv6_probe_addrs = []
[retry]
reconnect_initial_ms = 10000
reconnect_max_ms = 10000
"""

            def server_ready():
                if processes[0].poll() is not None:
                    raise AssertionError(server_log.read_text())
                return "proxy listening" in server_log.read_text()

            wait_for(server_ready, "server did not start")
            a, a_log = start("client", "a", client_config("a"))
            b, b_log = start("client", "b", client_config("b"))
            wait_for(lambda: server_log.read_text().count("control stream established") == 2,
                     "both clients did not register")
            origins = []
            for _ in range(2):
                origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
                stack.callback(origin.server_close)
                stack.callback(origin.shutdown)
                threading.Thread(target=origin.serve_forever, daemon=True).start()
                origins.append(origin.server_port)

            def request(proxy_port, origin_port, path):
                with socket.create_connection(("127.0.0.1", proxy_port), timeout=3) as browser:
                    browser.sendall(
                        f"GET http://127.0.0.1:{origin_port}/{path} HTTP/1.1\r\n"
                        f"Host: 127.0.0.1:{origin_port}\r\n\r\n".encode()
                    )
                    data = b""
                    while chunk := browser.recv(65536):
                        data += chunk
                    return data

            def assert_ok(proxy_port, origin_port, path):
                response = request(proxy_port, origin_port, path)
                self.assertIn(b"200 OK", response)
                self.assertTrue(response.endswith(f"/{path}".encode()), response)

            assert_ok(a_port, origins[0], "from-a")
            assert_ok(b_port, origins[1], "from-b")
            self.assertIn(f"-> 127.0.0.1:{origins[0]}", a_log.read_text())
            self.assertNotIn(f"-> 127.0.0.1:{origins[0]}", b_log.read_text())
            self.assertIn(f"-> 127.0.0.1:{origins[1]}", b_log.read_text())
            self.assertNotIn(f"-> 127.0.0.1:{origins[1]}", a_log.read_text())

            # Keep a B CONNECT alive across A's replacement and subsequent outage.
            target = stack.enter_context(socket.socket())
            target.bind(("127.0.0.1", 0))
            target.listen()
            target.settimeout(3)
            browser = stack.enter_context(socket.create_connection(("127.0.0.1", b_port), timeout=3))
            browser.sendall(f"CONNECT 127.0.0.1:{target.getsockname()[1]} HTTP/1.1\r\n\r\n".encode())
            peer = stack.enter_context(target.accept()[0])
            peer.settimeout(3)
            self.assertIn(b"200 Connection established", read_until(browser, b"\r\n\r\n"))

            # Pause A so it cannot reconnect and steal the session back.
            a.send_signal(signal.SIGSTOP)
            replacement, replacement_log = start("client", "a-new", client_config("a"))
            wait_for(lambda: server_log.read_text().count("control stream established") == 3,
                     "replacement did not register")
            assert_ok(a_port, origins[0], "replacement")
            self.assertIn(f"-> 127.0.0.1:{origins[0]}", replacement_log.read_text())
            browser.sendall(b"b-still-alive")
            self.assertEqual(read_until(peer, b"b-still-alive"), b"b-still-alive")
            stop(a)
            stop(replacement)
            wait_for(lambda: b"502 Bad Gateway" in request(a_port, origins[0], "offline"),
                     "offline A did not return 502")
            assert_ok(b_port, origins[1], "b-after-a-offline")
            peer.sendall(b"b-still-replies")
            self.assertEqual(read_until(browser, b"b-still-replies"), b"b-still-replies")

            # A trusted CA alone is insufficient: CN must have a configured route.
            unknown, _ = start("client", "unknown", client_config("unknown"))
            wait_for(lambda: "rejecting unconfigured tunnel client" in server_log.read_text(),
                     "unknown identity was not rejected")
            stop(unknown)
            assert_ok(b_port, origins[1], "b-after-unknown")

            # Same CN signed by an untrusted CA must fail TLS before routing.
            foreign = directory / "foreign"
            subprocess.run([REP, "cert", "init", "localhost", "--out", foreign],
                           check=True, capture_output=True)
            subprocess.run([REP, "cert", "issue-client", "--name", "b",
                            "--config", foreign / "server.toml"], check=True, capture_output=True)
            impostor, _ = start("client", "impostor", client_config("b", "foreign/certs"))
            wait_for(lambda: "tunnel tls handshake failed" in server_log.read_text(),
                     "untrusted CA was not rejected")
            stop(impostor)
            assert_ok(b_port, origins[1], "b-after-impostor")
            self.assertEqual(server_log.read_text().count("control stream established"), 3)
            self.assertIsNone(b.poll())


if __name__ == "__main__":
    unittest.main()
