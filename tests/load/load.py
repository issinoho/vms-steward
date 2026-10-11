"""load.py - Phase 5 load run: many clients, a mixed workload, for a while.

    python3 tests/load/load.py fcgi <binary> [seconds] [clients]
        Starts <binary> (build/steward or build/steward-asan, stub platform) on a
        loopback port and drives it over FastCGI, as lighttpd would. Measures the
        process's resident memory after a warm-up and at the end.
    python3 tests/load/load.py http <base-url> <username> [seconds] [clients]
        Drives an installed Steward over HTTP(S), e.g. http://node:8443. The password
        is read from STEWARD_LOAD_PASSWORD, never from the command line or a file.
        Signs in ONCE per client and reuses the session: repeated sign-ins would
        trip OpenVMS's break-in detection.

Each client loops over what a browser does: who am I, the dashboard (as a
background poll), users, a user, identifiers, holders, access history, switching
privileges on and off. It also sends what an attacker would: no session, a forged
cookie, a missing CSRF token, a foreign Origin, malformed and oversized bodies, bad
paths. Every answer must be the expected status. A 5xx, a dropped connection or a
wrong status is a failure. Read-only: no user or identifier is changed.
"""
import json
import os
import random
import socket
import ssl
import subprocess
import sys
import threading
import time
import http.client
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from fcgi_client import request  # noqa: E402

GATEWAY = "load-gateway-secret-0123456789abcdef"


class FcgiTransport:
    def __init__(self, addr):
        self.addr = addr

    def send(self, method, path, headers, data):
        params = {"REQUEST_METHOD": method, "REQUEST_URI": path, "REMOTE_ADDR": "127.0.0.1",
                  "HTTP_HOST": "steward.example", "SERVER_PROTOCOL": "HTTP/1.1",
                  "HTTP_X_STEWARD_GATEWAY": GATEWAY}
        for k, v in headers.items():
            params["HTTP_" + k.upper().replace("-", "_")] = v
        if data:
            params["CONTENT_TYPE"] = headers.get("Content-Type", "application/json")
            params["CONTENT_LENGTH"] = str(len(data))
        st, hdrs, body = request(self.addr, params, data, timeout=30)
        return st, hdrs, body


class HttpTransport:
    def __init__(self, base):
        u = urllib.parse.urlsplit(base)
        self.https = u.scheme == "https"
        self.host, self.port = u.hostname, u.port or (443 if self.https else 80)
        self.prefix = u.path.rstrip("/")
        self.origin = "%s://%s" % (u.scheme, u.netloc)
        self.local = threading.local()

    def conn(self):
        c = getattr(self.local, "c", None)
        if c is None:
            if self.https:
                c = http.client.HTTPSConnection(self.host, self.port, timeout=30,
                                                context=ssl.create_default_context())
            else:
                c = http.client.HTTPConnection(self.host, self.port, timeout=30)
            self.local.c = c
        return c

    def send(self, method, path, headers, data):
        h = dict(headers)
        h.setdefault("Host", "%s:%d" % (self.host, self.port))
        if method not in ("GET", "HEAD") and "Origin" not in h:
            h["Origin"] = self.origin
        if data:
            h.setdefault("Content-Type", "application/json")
        for attempt in (0, 1):
            c = self.conn()
            try:
                c.request(method, self.prefix + path, body=data or None, headers=h)
                r = c.getresponse()
                body = r.read()
                return r.status, r.getheaders(), body
            except (http.client.HTTPException, OSError):
                c.close()
                self.local.c = None
                if attempt:
                    raise
        return None


class Browser:
    def __init__(self, t):
        self.t, self.cookie, self.csrf = t, None, None

    def call(self, method, path, body=None, csrf=True, headers=None, raw=None):
        h = {}
        if self.cookie:
            h["Cookie"] = "steward_session=" + self.cookie
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            h["X-Steward-CSRF"] = self.csrf
        h.update(headers or {})
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
        st, hdrs, payload = self.t.send(method, path, h, data)
        for name, value in hdrs:
            if name.lower() == "set-cookie" and value.startswith("steward_session="):
                self.cookie = value.split(";")[0].split("=", 1)[1] or None
        try:
            doc = json.loads(payload) if payload else None
        except ValueError:
            doc = None
        if isinstance(doc, dict) and "csrf" in doc:
            self.csrf = doc["csrf"]
        return st, doc


lock = threading.Lock()
stats = {"requests": 0, "failures": 0, "by_status": {}}
failures = []


def expect(what, got, want):
    with lock:
        stats["requests"] += 1
        stats["by_status"][got] = stats["by_status"].get(got, 0) + 1
        ok = got in want if isinstance(want, tuple) else got == want
        if not ok:
            stats["failures"] += 1
            if len(failures) < 20:
                failures.append("%s: got %s, wanted %s" % (what, got, want))


def client(t, user, password, deadline, n):
    b = Browser(t)
    st, doc = b.call("POST", "/api/v1/session", {"username": user, "password": password})
    expect("sign in" + (" (%s)" % doc.get("title") if isinstance(doc, dict) and st != 201 else ""), st, 201)
    if st != 201:
        return
    target = user.upper()
    while time.time() < deadline:
        step = random.randrange(14)
        try:
            if step == 0:
                st, doc = b.call("GET", "/api/v1/session"); expect("whoami", st, 200)
            elif step == 1:
                st, _ = b.call("GET", "/api/v1/system", headers={"X-Steward-Background": "1"}); expect("dashboard poll", st, 200)
            elif step == 2:
                st, _ = b.call("GET", "/api/v1/users?limit=50"); expect("users", st, (200, 403))
            elif step == 3:
                st, _ = b.call("GET", "/api/v1/users/" + target); expect("own record", st, 200)
            elif step == 4:
                st, _ = b.call("GET", "/api/v1/identifiers?type=all&limit=50"); expect("identifiers", st, (200, 403))
            elif step == 5:
                st, _ = b.call("GET", "/api/v1/users/%s/identifiers" % target); expect("held", st, (200, 403))
            elif step == 6:
                st, _ = b.call("GET", "/api/v1/access?since=%d&limit=200" % (int(time.time()) - 3600)); expect("access", st, 200)
            elif step == 7:
                st, _ = b.call("PUT", "/api/v1/session/privileges", {"enabled": ["SYSPRV"]}); expect("privileges on", st, (200, 403))
                st, _ = b.call("PUT", "/api/v1/session/privileges", {"enabled": []}); expect("privileges off", st, 200)
            elif step == 8:   # hostile: no session at all
                st, _ = Browser(t).call("GET", "/api/v1/users"); expect("no session", st, 401)
            elif step == 9:   # hostile: a forged cookie
                st, _ = Browser(t).call("GET", "/api/v1/session", headers={"Cookie": "steward_session=" + "ab" * 32}); expect("forged cookie", st, 401)
            elif step == 10:  # hostile: a change without the CSRF token, and from a foreign origin
                st, _ = b.call("PUT", "/api/v1/session/privileges", {"enabled": []}, csrf=False); expect("no CSRF", st, 403)
                st, _ = b.call("PUT", "/api/v1/session/privileges", {"enabled": []}, headers={"Origin": "https://evil.example"}); expect("foreign origin", st, 403)
            elif step == 11:  # hostile: malformed and oversized bodies
                st, _ = b.call("PUT", "/api/v1/session/privileges", raw=b'{"enabled": [');  expect("malformed JSON", st, 400)
                st, _ = b.call("PUT", "/api/v1/session/privileges", raw=b'{"enabled":["' + b"A" * 70000 + b'"]}'); expect("a long name", st, 422)
                st, _ = b.call("PUT", "/api/v1/session/privileges", raw=b'{"enabled":["' + b"A" * 300000 + b'"]}'); expect("over the body limit", st, 413)
            elif step == 12:  # hostile: odd paths and parameters
                st, _ = b.call("GET", "/api/v1/users/" + "%00X"); expect("NUL in a name", st, (400, 404))
                st, _ = b.call("GET", "/api/v1/../../etc/passwd"); expect("path traversal", st, (400, 404))
                st, _ = b.call("GET", "/api/v1/access?since=-1"); expect("bad time", st, 400)
            else:
                st, _ = b.call("GET", "/api/v1/users/NO_SUCH_USER_X"); expect("no such user", st, (403, 404))
        except Exception as ex:  # a dropped connection or a hang: a failure
            expect("exception %s" % type(ex).__name__, None, 0)
    st, _ = b.call("DELETE", "/api/v1/session")
    expect("sign out", st, 204)


def rss_kb(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def run(t, user, password, seconds, clients):
    deadline = time.time() + seconds
    threads = [threading.Thread(target=client, args=(t, user, password, deadline, i)) for i in range(clients)]
    for th in threads:
        th.start()
    return threads


def report(t0, extra=""):
    took = time.time() - t0
    print("%d requests in %.0fs (%.0f/s), %d failures%s" % (stats["requests"], took, stats["requests"] / took,
                                                            stats["failures"], extra))
    print("by status:", dict(sorted(stats["by_status"].items(), key=lambda kv: str(kv[0]))))
    for f in failures:
        print("FAIL", f)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "fcgi":
        binary = sys.argv[2]
        seconds = int(sys.argv[3]) if len(sys.argv) > 3 else 60
        clients = int(sys.argv[4]) if len(sys.argv) > 4 else 8
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        env = dict(os.environ, STEWARD_GATEWAY_SECRET=GATEWAY, STEWARD_AUDIT_FILE="/dev/null",
                   ASAN_OPTIONS="abort_on_error=1:detect_leaks=0")
        proc = subprocess.Popen([binary, "-b", "127.0.0.1:%d" % port], env=env, stderr=subprocess.PIPE)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close(); break
            except OSError:
                time.sleep(0.1)
        t = FcgiTransport(("127.0.0.1", port))
        t0 = time.time()
        # Warm up for a tenth of the run, then measure memory; it must not keep growing.
        threads = run(t, "steward_adm", "admin-pass", seconds, clients)
        time.sleep(max(5, seconds / 10))
        rss0 = rss_kb(proc.pid)
        for th in threads:
            th.join()
        rss1 = rss_kb(proc.pid)
        alive = proc.poll() is None
        proc.terminate()
        err = proc.stderr.read().decode(errors="replace")
        sanitizer = [l for l in err.splitlines() if "Sanitizer" in l or "runtime error" in l]
        report(t0, "; RSS %d kB after warm-up, %d kB at the end" % (rss0, rss1))
        # Under ASan the quarantine holds freed memory on purpose, so memory is judged
        # on the plain build only; the ASan run is for memory errors.
        grew = "asan" not in os.path.basename(binary) and rss1 > rss0 + 2048
        bad = stats["failures"] or not alive or sanitizer or grew
        if not alive:
            print("FAIL the server died")
        for l in sanitizer[:10]:
            print("FAIL", l)
        if grew:
            print("FAIL memory grew by %d kB under steady load" % (rss1 - rss0))
        sys.exit(1 if bad else 0)
    elif mode == "http":
        base, user = sys.argv[2], sys.argv[3]
        seconds = int(sys.argv[4]) if len(sys.argv) > 4 else 60
        clients = int(sys.argv[5]) if len(sys.argv) > 5 else 4
        password = os.environ.get("STEWARD_LOAD_PASSWORD")
        if not password:
            sys.exit("load.py: set STEWARD_LOAD_PASSWORD")
        t0 = time.time()
        for th in run(HttpTransport(base), user, password, seconds, clients):
            th.join()
        report(t0)
        sys.exit(1 if stats["failures"] else 0)
    sys.exit(__doc__)


if __name__ == "__main__":
    main()
