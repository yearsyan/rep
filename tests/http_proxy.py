"""End-to-end proxy regression: cargo build --locked && python3 tests/http_proxy.py.

Uses temporary certificates and loopback listeners only; all subprocesses are
stopped on exit. Tests HTTP body boundaries and CONNECT forwarding.
"""

import gzip
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parents[1]
REP = Path(os.environ.get('REP_BIN', ROOT / 'target/debug/rep'))


def listener(stack):
    sock = stack.enter_context(socket.socket())
    sock.bind(('127.0.0.1', 0))
    sock.listen()
    sock.settimeout(3)
    return sock


def read_until(sock, marker):
    data = b''
    while marker not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


with tempfile.TemporaryDirectory(prefix='rep-pipeline-check-') as directory, ExitStack() as stack:
    directory = Path(directory)
    origin_a, origin_b = listener(stack), listener(stack)
    tunnel, proxy = listener(stack), listener(stack)
    tunnel_port, proxy_port = tunnel.getsockname()[1], proxy.getsockname()[1]
    a_port, b_port = origin_a.getsockname()[1], origin_b.getsockname()[1]
    subprocess.run([REP, 'cert', 'init', 'localhost', '--out', directory], check=True, capture_output=True)
    (directory / 'server.toml').write_text(f'[tunnel]\nlisten = "127.0.0.1:{tunnel_port}"\n[proxy]\nlisten = "127.0.0.1:{proxy_port}"\n')
    (directory / 'client.toml').write_text(f'server_addr = "127.0.0.1:{tunnel_port}"\nserver_name = "localhost"\nipv6_probe_addrs = []\n[retry]\nreconnect_initial_ms = 100\nreconnect_max_ms = 200\n')
    server_log = stack.enter_context((directory / 'server.log').open('w'))
    client_log = stack.enter_context((directory / 'client.log').open('w'))
    tunnel.close()
    proxy.close()
    processes = []
    try:
        for role, logfile in [('server', server_log), ('client', client_log)]:
            processes.append(subprocess.Popen([REP, role, '--config', directory / f'{role}.toml'], stdout=logfile, stderr=subprocess.STDOUT, env={**os.environ, 'RUST_LOG': 'info'}))
        deadline = time.monotonic() + 10
        while 'control stream established' not in (directory / 'server.log').read_text():
            if any(proc.poll() is not None for proc in processes) or time.monotonic() > deadline:
                raise RuntimeError((directory / 'server.log').read_text() + (directory / 'client.log').read_text())
            time.sleep(0.05)
        results = []
        compressed = gzip.compress(b'compressed request body')
        chunked_gzip = f'{len(compressed):x}\r\n'.encode() + compressed + b'\r\n0\r\n\r\n'
        cases = [
            ('GET', b'', b''),
            ('POST', b'Content-Length: 0\r\n', b''),
            ('POST', b'Content-Length: 4\r\n', b'test'),
            ('POST', b'Transfer-Encoding: chunked\r\n', b'4;note="value"\r\ntest\r\n0\r\nChecksum: value\r\n\r\n'),
            ('POST', b'Transfer-Encoding: gzip, chunked\r\n', chunked_gzip),
        ]
        second = f'GET http://127.0.0.1:{b_port}/second HTTP/1.1\r\nHost: 127.0.0.1:{b_port}\r\n\r\n'.encode()
        final_response = b'HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nfirst-only'

        def read_all(sock):
            data = b''
            while chunk := sock.recv(65536):
                data += chunk
            return data

        for mode in ['one_write', 'separate_writes_before_response']:
            for method, headers, body in cases:
                first_head = f'{method} http://127.0.0.1:{a_port}/first HTTP/1.1\r\nHost: 127.0.0.1:{a_port}\r\n'.encode() + headers + b'\r\n'
                with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as browser:
                    browser.sendall(first_head + body + second if mode == 'one_write' else first_head + body)
                    connection, _ = origin_a.accept()
                    with connection:
                        connection.settimeout(3)
                        # Request completion must reach A without waiting for the browser to close.
                        captured = read_all(connection)
                        if mode == 'separate_writes_before_response':
                            browser.sendall(second)
                            assert connection.recv(1) == b''
                        forwarded_head, actual_body = captured.split(b'\r\n\r\n', 1)
                        assert forwarded_head.startswith(f'{method} /first HTTP/1.1\r\n'.encode()), captured
                        assert b'connection: close' in forwarded_head.lower(), captured
                        assert actual_body == body, (mode, headers, actual_body)
                        assert second not in captured, captured
                        connection.sendall(final_response)
                    reply = read_all(browser)
                    assert reply == final_response, reply
                results.append({'mode': mode, 'method': method, 'headers': headers.decode().strip(), 'second_request_reached_a': False})

        # Origin can issue 100 Continue while the body is still pending.
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as browser:
            browser.sendall(f'POST http://127.0.0.1:{a_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{a_port}\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\n'.encode())
            connection, _ = origin_a.accept()
            with connection:
                connection.settimeout(3)
                captured = read_until(connection, b'\r\n\r\n')
                assert captured.endswith(b'\r\n\r\n')
                connection.sendall(b'HTTP/1.1 100 Continue\r\n\r\n')
                assert read_until(browser, b'\r\n\r\n') == b'HTTP/1.1 100 Continue\r\n\r\n'
                browser.sendall(b'test' + second)
                assert read_all(connection) == b'test'
                connection.sendall(final_response)
            assert read_all(browser) == final_response
        results.append({'expect_100_continue': 'passed'})

        # A final response must not wait for the rest of an unfinished upload.
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as browser:
            browser.sendall(f'POST http://127.0.0.1:{a_port}/upload HTTP/1.1\r\nHost: 127.0.0.1:{a_port}\r\nContent-Length: 100\r\n\r\n'.encode())
            connection, _ = origin_a.accept()
            rejection = b'HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
            with connection:
                connection.settimeout(3)
                read_until(connection, b'\r\n\r\n')
                connection.sendall(rejection)
            assert read_all(browser) == rejection
        results.append({'early_final_response': 'passed'})

        # Header values may contain non-UTF-8 bytes and must reach the origin unchanged.
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as browser:
            headers = b'X-Label: caf\xe9\r\nIf-Match: "\xff"\r\n'
            browser.sendall(f'GET http://127.0.0.1:{a_port}/headers HTTP/1.1\r\nHost: wrong.example\r\n'.encode() + headers + b'\r\n')
            connection, _ = origin_a.accept()
            with connection:
                connection.settimeout(3)
                captured = read_all(connection)
                assert b'x-label: caf\xe9\r\n' in captured, captured
                assert b'if-match: "\xff"\r\n' in captured, captured
                assert b'\xef\xbf\xbd' not in captured, captured
                connection.sendall(final_response)
            assert read_all(browser) == final_response
        results.append({'non_utf8_header_values': 'passed'})

        # CONNECT includes early data and remains an unrestricted bidirectional byte tunnel.
        with socket.create_connection(('127.0.0.1', proxy_port), timeout=3) as browser:
            browser.sendall(f'CONNECT 127.0.0.1:{a_port} HTTP/1.1\r\nHost: 127.0.0.1:{a_port}\r\n\r\n'.encode() + b'early-data')
            connection, _ = origin_a.accept()
            with connection:
                connection.settimeout(3)
                assert read_until(connection, b'early-data') == b'early-data'
                assert read_until(browser, b'\r\n\r\n') == b'HTTP/1.1 200 Connection established\r\n\r\n'
                connection.sendall(b'first-reply')
                assert read_until(browser, b'first-reply') == b'first-reply'
                browser.sendall(b'later-data')
                assert read_until(connection, b'later-data') == b'later-data'
                connection.sendall(b'second-reply')
                assert read_until(browser, b'second-reply') == b'second-reply'
            browser.shutdown(socket.SHUT_WR)
            assert read_all(browser) == b''
        results.append({'connect_early_and_later_data': 'passed'})

        origin_b.settimeout(0.2)
        try:
            other, _ = origin_b.accept()
        except socket.timeout:
            pass
        else:
            other.close()
            raise AssertionError('Proxy unexpectedly opened a second target for a discarded request')
        print(json.dumps(results, ensure_ascii=False, indent=2))
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
        for process in processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
