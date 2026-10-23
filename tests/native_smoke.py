"""Unprivileged Linux native tunnel test; no system services or production hosts.

python3 tests/native_smoke.py --server-archive FILE --client FILE --sample FILE
"""
import argparse
import contextlib
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import select
import socket
import socketserver
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tuna_dns import config, diagnostics


class HTTP(http.server.BaseHTTPRequestHandler):
    count = 0

    def do_GET(self):
        type(self).count += 1
        body = b'tuna-dns-native-proof'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class Socks(socketserver.BaseRequestHandler):
    count = 0
    require_auth = False

    def handle(self):
        try:
            s = self.request
            s.settimeout(12)
            version, n = diagnostics.read_exact(s, 2)
            assert version == 5
            methods = diagnostics.read_exact(s, n)
            method = 2 if self.require_auth else 0
            if method not in methods:
                s.sendall(b'\x05\xff'); return
            s.sendall(bytes((5, method)))
            if method == 2:
                version, n = diagnostics.read_exact(s, 2)
                user = diagnostics.read_exact(s, n)
                n = diagnostics.read_exact(s, 1)[0]
                password = diagnostics.read_exact(s, n)
                good = (version, user, password) == (1, b'tuna-test', b'synthetic-only')
                s.sendall(bytes((1, 0 if good else 1)))
                if not good:
                    return
            version, command, _, kind = diagnostics.read_exact(s, 4)
            assert version == 5 and command == 1
            if kind == 1:
                host = socket.inet_ntoa(diagnostics.read_exact(s, 4))
            elif kind == 3:
                host = diagnostics.read_exact(s, diagnostics.read_exact(s, 1)[0]).decode()
            else:
                raise ValueError('Unexpected address')
            port = struct.unpack('!H', diagnostics.read_exact(s, 2))[0]
            with socket.create_connection((host, port), timeout=10) as upstream:
                type(self).count += 1
                s.sendall(b'\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00')
                while True:
                    ready, _, _ = select.select([s, upstream], [], [], 10)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(65536)
                        if not data:
                            return
                        (upstream if source is s else s).sendall(data)
        except (OSError, ValueError, RuntimeError, AssertionError):
            return


class SocksServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@contextlib.contextmanager
def serving(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=3)


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill(); process.wait()


def run_case(root, binary, client, sample, mode, target_port, proxy_port):
    work = root / mode; work.mkdir(mode=0o700)
    settings = config.defaults()
    settings.update(domains=['d.tuna.invalid', 'd1.tuna.invalid'], listen_host='127.0.0.1', port=free_port(socket.SOCK_DGRAM))
    if mode != 'direct':
        settings['route'].update(mode='socks5', host='127.0.0.1', port=proxy_port)
        if mode == 'auth':
            settings['route'].update(username='tuna-test', password='synthetic-only')
    key_file = work / 'key'; key_file.write_text(settings['key']); key_file.chmod(0o600)
    (work / 'server.toml').write_text(config.render(settings, str(key_file)))
    client_port = free_port()
    values = dict(DOMAINS=settings['domains'], DATA_ENCRYPTION_METHOD=5, ENCRYPTION_KEY=settings['key'],
                  LISTEN_IP='127.0.0.1', LISTEN_PORT=client_port, LOCAL_DNS_ENABLED=False,
                  LOCAL_DNS_CACHE_PERSIST_TO_FILE=False, STARTUP_MODE='resolvers',
                  UPLOAD_COMPRESSION_TYPE=2, DOWNLOAD_COMPRESSION_TYPE=2, RX_TX_WORKERS=16,
                  TUNNEL_PROCESS_WORKERS=0, SOCKS5_AUTH=False, RESOLVER_BALANCING_STRATEGY=3)
    text = sample
    for key, value in values.items():
        text, n = re.subn(r'^' + key + r'\s*=.*$', lambda _: key + ' = ' + json.dumps(value), text, flags=re.M)
        if n != 1:
            raise RuntimeError('Client sample missing ' + key)
    (work / 'client.toml').write_text(text)
    (work / 'resolvers.txt').write_text(f"127.0.0.1:{settings['port']}\n")
    before_http, before_socks = HTTP.count, Socks.count
    with (work / 'server.log').open('wb') as server_log, (work / 'client.log').open('wb') as client_log:
        server = subprocess.Popen([str(binary), '-config', str(work / 'server.toml')], cwd=work, stdout=server_log, stderr=server_log)
        client_process = None
        try:
            time.sleep(.4)
            assert server.poll() is None, 'Native server exited'
            client_process = subprocess.Popen([str(client), '-config', str(work / 'client.toml'), '-resolvers', str(work / 'resolvers.txt')], cwd=work, stdout=client_log, stderr=client_log)
            deadline = time.monotonic() + 40
            while True:
                assert server.poll() is None and client_process.poll() is None, 'Native process exited'
                try:
                    with socket.create_connection(('127.0.0.1', client_port), timeout=.3):
                        break
                except OSError:
                    if time.monotonic() > deadline:
                        raise RuntimeError('Client listener timeout')
                    time.sleep(.2)
            route = dict(mode='socks5', host='127.0.0.1', port=client_port, username='', password='')
            if mode == 'unavailable':
                try:
                    diagnostics.probe(route, f'http://203.0.113.1:{target_port}/proof')
                except (OSError, RuntimeError, http.client.HTTPException):
                    pass
                else:
                    raise AssertionError('Unavailable external SOCKS fell back to Direct')
                assert HTTP.count == before_http, 'HTTP escaped via Direct'
            else:
                assert diagnostics.probe(route, f'http://203.0.113.1:{target_port}/proof') == 200
                assert HTTP.count > before_http
                assert (Socks.count > before_socks) == (mode != 'direct')
            print('PASS native', mode, flush=True)
        except BaseException:
            # Logs contain only synthetic credentials; retain them if test fails.
            print('Native diagnostic files:', work, file=sys.stderr)
            raise
        finally:
            if client_process:
                stop(client_process)
            stop(server)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-archive', type=Path, required=True)
    parser.add_argument('--client', type=Path, required=True)
    parser.add_argument('--sample', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.server_archive.read_bytes()).hexdigest() == '597bdc510b896a3b4ac89865ee7cefa73191025c64093f5e0f85c76a70430de9'
    # mkdtemp deliberately retains synthetic failure evidence, never real keys.
    root = Path(tempfile.mkdtemp(prefix='tuna-dns-native-'))
    binary = root / 'server'
    with tarfile.open(args.server_archive) as archive:
        member = next(m for m in archive.getmembers() if m.isfile() and m.name.startswith('MasterDnsVPN_Server_Linux_AMD64_'))
        binary.write_bytes(archive.extractfile(member).read()); binary.chmod(0o700)
    client = root / 'client'; client.write_bytes(args.client.read_bytes()); client.chmod(0o700)
    sample = args.sample.read_text()
    with serving(http.server.ThreadingHTTPServer(('203.0.113.1', 0), HTTP)) as httpd:
        run_case(root, binary, client, sample, 'direct', httpd.server_port, free_port())
        with serving(SocksServer(('127.0.0.1', 0), Socks)) as proxy:
            run_case(root, binary, client, sample, 'socks', httpd.server_port, proxy.server_address[1])
            Socks.require_auth = True
            run_case(root, binary, client, sample, 'auth', httpd.server_port, proxy.server_address[1])
        run_case(root, binary, client, sample, 'unavailable', httpd.server_port, free_port())
    print('Native smoke evidence:', root)


if __name__ == '__main__':
    main()
