"""Strict TLS regression: cargo build --locked && python3.14 tests/tls_certificates.py.

Uses only Python's standard library and the built rep executable. Certificates are
created in a temporary directory; both sides verify the peer with default flags.
"""

import os
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REP = Path(os.environ.get("REP_BIN", ROOT / "target/debug/rep"))


def strict_handshake(cert_dir, client_name):
    ca = cert_dir / "ca.pem"
    client = ssl.create_default_context(cafile=ca)
    server = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH, cafile=ca)
    assert client.verify_flags & ssl.VERIFY_X509_STRICT, "Use Python 3.13+"
    assert server.verify_flags & ssl.VERIFY_X509_STRICT, "Use Python 3.13+"
    server.verify_mode = ssl.CERT_REQUIRED
    server.load_cert_chain(cert_dir / "server.pem", cert_dir / "server.key")
    client.load_cert_chain(cert_dir / f"{client_name}.pem", cert_dir / f"{client_name}.key")
    client_in, client_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    server_in, server_out = ssl.MemoryBIO(), ssl.MemoryBIO()
    peers = [
        client.wrap_bio(client_in, client_out, server_hostname="localhost"),
        server.wrap_bio(server_in, server_out, server_side=True),
    ]
    done = [False, False]
    for _ in range(20):
        for i, peer in enumerate(peers):
            if not done[i]:
                try:
                    peer.do_handshake()
                    done[i] = True
                except ssl.SSLWantReadError:
                    pass
        if data := client_out.read():
            server_in.write(data)
        if data := server_out.read():
            client_in.write(data)
        if all(done):
            return
    raise AssertionError("TLS handshake did not complete")


class CertificateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="rep-tls-test-")
        cls.addClassCleanup(cls.temp.cleanup)
        cls.output = Path(cls.temp.name)
        subprocess.run([REP, "cert", "init", "localhost", "--out", cls.output],
                       check=True, capture_output=True, text=True)
        subprocess.run([REP, "cert", "issue-client", "--name", "additional",
                        "--config", cls.output / "server.toml"],
                       check=True, capture_output=True, text=True)

    def test_initial_certificates_with_python_default_strict_verification(self):
        strict_handshake(self.output / "certs", "client")

    def test_issued_client_with_python_default_strict_verification(self):
        strict_handshake(self.output / "certs", "additional")


if __name__ == "__main__":
    unittest.main()
