"""devserver.py - work on the front end on Linux, against steward on the stub platform.

    make dev        (or: python3 tools/devserver.py build/steward [port])

Serves www/ and passes /api/ to a steward process over FastCGI, as lighttpd does on
OpenVMS, at http://127.0.0.1:8080/. Plain HTTP, so it starts steward with
STEWARD_INSECURE_COOKIE=1; nothing else should ever set that. Stub accounts are
listed in src/plat/stub/st_plat_stub.c (e.g. STEWARD_TEST / test-pass).

Set DEV_PREFIX=/steward to serve under a prefix, as a reverse proxy would (D7).
Add ?shot=1 to the page URL for headless screenshots: the page's load event then
waits until the first view has rendered.
"""
import http.server
import mimetypes
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from fcgi_client import request  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "www")
PREFIX = os.environ.get("DEV_PREFIX", "").rstrip("/")
FCGI = ("127.0.0.1", 19190)

# The page-level headers lighttpd sets in vms/steward.conf, so the dev server
# exercises the same CSP.
PAGE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; img-src 'self'; style-src 'self'; "
                               "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
                               "base-uri 'none'; form-action 'self'",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


class Handler(http.server.BaseHTTPRequestHandler):
    def _strip(self):
        path = self.path
        if PREFIX:
            if not path.startswith(PREFIX + "/"):
                return None
            path = path[len(PREFIX):]
        return path

    def _api(self, path):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        params = {
            "REQUEST_METHOD": self.command, "REQUEST_URI": path,
            "REMOTE_ADDR": self.client_address[0], "SERVER_PROTOCOL": "HTTP/1.1",
        }
        for k, v in self.headers.items():
            key = k.upper().replace("-", "_")
            if key == "CONTENT_TYPE":
                params["CONTENT_TYPE"] = v
            elif key == "CONTENT_LENGTH":
                params["CONTENT_LENGTH"] = v
            else:
                params["HTTP_" + key] = v
        if PREFIX:
            # Pretend to be a trusted proxy publishing us under the prefix.
            params["HTTP_X_FORWARDED_PREFIX"] = PREFIX
        status, headers, payload = request(FCGI, params, body)
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def _static(self, path):
        rel = path.split("?")[0].lstrip("/") or "index.html"
        if rel == "__hold":
            # Screenshot mode: an image the page waits for, so headless
            # "firefox --screenshot" (which fires at load) sees the rendered view.
            time.sleep(1.5)
            self.send_response(204)
            self.end_headers()
            return
        full = os.path.realpath(os.path.join(ROOT, rel))
        if not full.startswith(os.path.realpath(ROOT)) or not os.path.isfile(full):
            self.send_error(404)
            return
        with open(full, "rb") as f:
            data = f.read()
        if rel == "index.html" and "shot=1" in path:
            data = data.replace(b"</body>", b'<img src="__hold" alt="" hidden></body>')
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(full)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        for k, v in PAGE_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _dev_login(self, path):
        # Dev-only shortcut for screenshots: sign a stub account in and land on the
        # app. Only meaningful against the stub platform, whose fixed test
        # passwords are listed in st_plat_stub.c.
        stub = {"STEWARD_TEST": "test-pass", "STEWARD_ADM": "admin-pass"}
        user = path.split("user=")[-1].split("&")[0].upper() if "user=" in path else "STEWARD_ADM"
        body = ('{"username":"%s","password":"%s"}' % (user, stub.get(user, ""))).encode()
        params = {"REQUEST_METHOD": "POST", "REQUEST_URI": "/api/v1/session",
                  "REMOTE_ADDR": "127.0.0.1", "HTTP_HOST": self.headers.get("Host", ""),
                  "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body))}
        status, headers, _ = request(FCGI, params, body)
        self.send_response(302)
        for name, value in headers:
            if name.lower() == "set-cookie":
                self.send_header(name, value)
        self.send_header("Location", (PREFIX or "") + "/?shot=1#/account")
        self.end_headers()

    def _any(self):
        path = self._strip()
        if path is None:
            self.send_error(404)
        elif path.startswith("/__login"):
            self._dev_login(path)
        elif path.startswith("/api/"):
            self._api(path)
        else:
            self._static(path)

    do_GET = do_POST = do_DELETE = do_PATCH = do_PUT = _any


def main():
    binary = sys.argv[1] if len(sys.argv) > 1 else "build/steward"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    env = dict(os.environ, STEWARD_INSECURE_COOKIE="1",
               STEWARD_TRUSTED_PROXIES="127.0.0.1" if PREFIX else "")
    proc = subprocess.Popen([binary, "-b", "%s:%d" % FCGI], env=env)
    for _ in range(50):
        try:
            socket.create_connection(FCGI, timeout=1).close()
            break
        except OSError:
            time.sleep(0.1)
    print("Steward dev server: http://127.0.0.1:%d%s/" % (port, PREFIX))
    try:
        http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
