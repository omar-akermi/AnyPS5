import http.server
import os
import subprocess
import sys
import threading
import time
import urllib.parse


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

    def respond(self):
        try:
            with self.server.started_lock:
                self.server.started.add(self.path)
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
            if self.path == "/echo":
                data = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            elif self.path == "/binary":
                data = bytes(range(256)) * 4
            elif self.path == "/missing":
                data = b"missing"
            else:
                data = b"hello\x00world"
            self.send_response(404 if self.path == "/missing" else 200)
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
        except (BrokenPipeError, ConnectionResetError):
            pass


if __name__ == "__main__":
    http.server.ThreadingHTTPServer.request_queue_size = 64
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.started = set()
    server.started_lock = threading.Lock()
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    try:
        environment = os.environ.copy()
        environment["http_proxy"] = "http://127.0.0.1:9"
        environment["ALL_PROXY"] = "http://127.0.0.1:9"
        environment["NO_PROXY"] = ""
        result = subprocess.run([sys.argv[1], f"http://127.0.0.1:{server.server_port}/", sys.argv[2]], timeout=20, env=environment)
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
    sys.exit(result.returncode)
