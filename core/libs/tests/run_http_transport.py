import http.server
import gzip
import os
import re
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import zlib
from pathlib import Path


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.respond()

    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST
    do_TRACE = do_POST

    def do_CONNECT(self):
        if self.path.startswith("rejected.invalid:"):
            self.send_error(403)
            return
        try:
            self.send_response(200)
            self.send_header("X-Tunnel-Target", self.path)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.write(bytes(range(256)) * 256)
            self.wfile.flush()
            if isinstance(self.connection, ssl.SSLSocket):
                self.connection.settimeout(2)
                self.connection.unwrap().close()
        except ConnectionError:
            pass
        self.close_connection = True

    def upload(self):
        if self.headers.get("Transfer-Encoding", "").lower() != "chunked":
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))
        chunks = []
        while True:
            size = int(self.rfile.readline().strip(), 16)
            if not size:
                self.rfile.readline()
                return b"".join(chunks)
            chunks.append(self.rfile.read(size))
            if self.rfile.read(2) != b"\r\n":
                raise ValueError("invalid chunk framing")

    def respond(self):
        try:
            if self.path == "/stall-upload":
                self.server.upload_release.wait(3)
            if self.path == "/release-upload":
                self.server.upload_release.set()
            with self.server.started_lock:
                self.server.started.add(self.path)
            if self.path.startswith("/redirect/") or self.path in ("/loop", "/downgrade"):
                code = 302 if self.path in ("/loop", "/downgrade") else int(self.path.rsplit("/", 1)[1])
                self.rfile.read(int(self.headers.get("Content-Length", 0)))
                self.send_response(code)
                location = "/loop" if self.path == "/loop" else "http://127.0.0.1:9/" if self.path == "/downgrade" else "/method"
                self.send_header("Location", location)
                self.send_header("Content-Length", "0" if code == 304 else "7")
                self.end_headers()
                if code != 304:
                    self.wfile.write(b"discard")
                return
            if self.path.startswith("/started?"):
                target = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)["path"][0]
                with self.server.started_lock:
                    active = target in self.server.started
                data = b"yes" if active else b"no"
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
                return
            if self.path.startswith("/slow/") or self.path == "/slow":
                time.sleep(0.4)
            if self.path == "/interim":
                self.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\n")
            if self.path in ("/chunked", "/badchunk"):
                self.wfile.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                self.wfile.write(b"5\r\nhello\r\n6\r\n\x00world\r\n")
                self.wfile.write(b"0\r\nX-Trailer: yes\r\n\r\n" if self.path == "/chunked" else b"invalid\r\n")
                self.close_connection = True
                return
            if self.path == "/truncated":
                self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
                self.close_connection = True
                return
            if self.path == "/method":
                data = self.command.encode() + b":" + self.rfile.read(int(self.headers.get("Content-Length", 0)))
            elif self.path in ("/cookies/check", "/outside-cookie"):
                data = self.headers.get("Cookie", "").encode()
            elif self.path in ("/echo", "/stall-upload"):
                data = self.upload()
            elif self.path == "/binary":
                data = bytes(range(256)) * 4
            elif self.path == "/missing":
                data = b"missing"
            elif self.path == "/sni":
                data = (getattr(self.connection, "http_sni", None) or "").encode()
            else:
                data = b"hello\x00world"
            self.send_response(404 if self.path == "/missing" else 200)
            if self.path == "/cookies/set":
                self.send_header("Set-Cookie", "session=alpha; Path=/cookies; HttpOnly")
                self.send_header("Set-Cookie", "expired=gone; Max-Age=0; Path=/")
                self.send_header("Set-Cookie", "foreign=bad; Domain=example.invalid; Path=/cookies")
            if self.path in ("/gzip", "/deflate"):
                data = gzip.compress(data) if self.path == "/gzip" else zlib.compress(data)
                self.send_header("Content-Encoding", self.path[1:])
            if self.path == "/badgzip":
                data = b"invalid-gzip"
                self.send_header("Content-Encoding", "gzip")
            self.send_header("X-Echo", ",".join(self.headers.get_all("X-Test", [])))
            self.send_header("X-Inherited", self.headers.get("X-Inherited", ""))
            self.send_header("X-Template", self.headers.get("X-Template", ""))
            if self.path == "/headers":
                self.send_header("X-Large", "x" * 1024)
            if self.path == "/close":
                self.send_header("Connection", "close")
                self.close_connection = True
            else:
                self.send_header("Content-Length", str(8 * 1024 * 1024 if self.path == "/large" else len(data)))
            self.end_headers()
            if self.path.startswith("/slowbody"):
                self.wfile.flush()
                time.sleep(0.4)
            if self.command != "HEAD":
                if self.path == "/large":
                    chunk = bytes(range(256)) * 32
                    for _ in range(1024):
                        self.wfile.write(chunk)
                else:
                    self.wfile.write(data)
        except ConnectionError:
            pass


class FixtureServer(http.server.ThreadingHTTPServer):
    request_queue_size = 64
    tls_context = None

    def finish_request(self, request, address):
        if self.tls_context is None:
            return super().finish_request(request, address)
        try:
            with self.tls_context.wrap_socket(request, server_side=True) as connection:
                super().finish_request(connection, address)
        except (ssl.SSLError, ConnectionError):
            pass


if __name__ == "__main__":
    temporary = tempfile.TemporaryDirectory()
    def certificate(name, header):
        source = Path(__file__).with_name(header).read_text(encoding="utf-8")
        contents = re.search(r"inline constexpr char " + name + r'\[\] = R"FIXTURE\((.*?)\)FIXTURE";', source, re.S).group(1)
        target = Path(temporary.name, name + ".pem")
        target.write_text(contents, encoding="ascii")
        return str(target)

    server = FixtureServer(("127.0.0.1", 0), Handler)
    server.upload_release = threading.Event()
    secure = sys.argv[2] in ("tls", "mutual", "expired", "async_tls", "tunnel_tls", "verification", "sni", "minimum12", "minimum13", "status_tls", "redirect_callbacks_tls")
    if secure:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3 if sys.argv[2] == "minimum13" else ssl.TLSVersion.TLSv1_2
        context.maximum_version = context.minimum_version
        context.set_servername_callback(lambda connection, name, _: setattr(connection, "http_sni", name))
        context.load_cert_chain(certificate("ExpiredPem" if sys.argv[2] == "expired" else "ServerPem", "HttpTlsFixture.hpp"),
                                certificate("ServerKey", "HttpTlsFixture.hpp"))
        if sys.argv[2] == "mutual":
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(certificate("RootPem", "SslCertificateFixture.hpp"))
        server.tls_context = context
    server.started = set()
    server.started_lock = threading.Lock()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        environment = os.environ.copy()
        environment["http_proxy"] = "http://127.0.0.1:9"
        environment["ALL_PROXY"] = "http://127.0.0.1:9"
        environment["NO_PROXY"] = ""
        host = "https://localhost" if secure else "http://localhost" if sys.argv[2] == "status" else "http://127.0.0.1"
        result = subprocess.run([sys.argv[1], f"{host}:{server.server_port}/", sys.argv[2]], timeout=20, env=environment)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
        temporary.cleanup()
    sys.exit(result.returncode)
