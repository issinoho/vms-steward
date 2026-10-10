"""test_api.py - drive the real steward binary (stub platform) over FastCGI.

make api-test. Starts build/steward on a free loopback port and plays the part of
lighttpd, and of nginx proxy manager in front of it, for the session lifecycle,
CSRF, origin checks and reverse-proxy handling (D7). Checks the audit log too.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "tools"))
from fcgi_client import request  # noqa: E402

checks = failures = 0
GATEWAY = "test-gateway-secret-0123456789abcdef"  # what lighttpd adds (vms/steward.conf)


def check(cond, what):
    global checks, failures
    checks += 1
    if not cond:
        failures += 1
        print("FAIL:", what)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Client:
    """One browser: keeps the cookie and CSRF token, sends what a browser would."""

    def __init__(self, addr, remote="127.0.0.1", extra=None):
        self.addr, self.remote, self.extra = addr, remote, extra or {}
        self.cookie, self.csrf = None, None

    def call(self, method, path, body=None, csrf=True, headers=None):
        params = {
            "REQUEST_METHOD": method, "REQUEST_URI": path, "REMOTE_ADDR": self.remote,
            "HTTP_HOST": "steward.example", "SERVER_PROTOCOL": "HTTP/1.1",
            "HTTP_X_STEWARD_GATEWAY": GATEWAY,
        }
        params.update(self.extra)
        data = b""
        if body is not None:
            data = json.dumps(body).encode()
            params["CONTENT_TYPE"] = "application/json"
            params["CONTENT_LENGTH"] = str(len(data))
        if self.cookie:
            params["HTTP_COOKIE"] = "steward_session=" + self.cookie
        if csrf and self.csrf and method not in ("GET", "HEAD"):
            params["HTTP_X_STEWARD_CSRF"] = self.csrf
        params.update(headers or {})
        status, hdrs, payload = request(self.addr, params, data)
        for name, value in hdrs:
            if name.lower() == "set-cookie" and value.startswith("steward_session="):
                self.cookie = value.split(";")[0].split("=", 1)[1] or None
        doc = json.loads(payload) if payload else None
        if isinstance(doc, dict) and "csrf" in doc:
            self.csrf = doc["csrf"]
        return status, dict(hdrs), doc


def main(binary):
    port = free_port()
    addr = ("127.0.0.1", port)
    audit = tempfile.NamedTemporaryFile(delete=False, suffix=".log")
    audit.close()
    env = dict(os.environ, STEWARD_AUDIT_FILE=audit.name,
               STEWARD_TRUSTED_PROXIES="127.0.0.2, 172.17.0.0/16",
               STEWARD_GATEWAY_SECRET=GATEWAY)
    proc = subprocess.Popen([binary, "-b", "127.0.0.1:%d" % port], env=env,
                            stderr=subprocess.PIPE)
    try:
        for _ in range(50):
            try:
                socket.create_connection(addr, timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)

        b = Client(addr)
        st, h, doc = b.call("GET", "/api/v1/health")
        check(st == 200 and doc == {"status": "ok"}, "health answers")
        check("default-src 'none'" in h.get("Content-Security-Policy", ""), "API responses carry a deny-all CSP")
        st, _, _ = b.call("GET", "/api/v1/health", headers={"HTTP_X_STEWARD_GATEWAY": ""})
        check(st == 403, "a request that bypasses lighttpd (no gateway secret) is refused")

        st, h, doc = b.call("GET", "/api/v1/session")
        check(st == 401 and h.get("Content-Type", "").startswith("application/problem+json"),
              "not signed in is a 401 problem")
        check(h.get("Cache-Control") == "no-store", "API responses are not cached")

        st, _, doc = b.call("POST", "/api/v1/session", {"username": "STEWARD_TEST", "password": "nope"})
        check(st == 401 and doc["title"] == "Sign-in failed", "wrong password")

        st, h, doc = b.call("POST", "/api/v1/session", {"username": "steward_test", "password": "test-pass"})
        check(st == 201 and b.cookie and len(b.csrf) == 64, "sign in")
        sc = h.get("Set-Cookie", "")
        check("Path=/api;" in sc and "HttpOnly" in sc and "Secure" in sc, "cookie attributes")

        st, _, doc = b.call("GET", "/api/v1/session")
        check(st == 200 and doc["username"] == "STEWARD_TEST" and doc["uic"] == "[362,1]",
              "whoami as the signed-in user, UIC in octal")

        st, _, _ = b.call("DELETE", "/api/v1/session", csrf=False)
        check(st == 403, "logout without CSRF refused")
        st, _, _ = b.call("DELETE", "/api/v1/session",
                          headers={"HTTP_ORIGIN": "https://evil.example"})
        check(st == 403, "logout from another origin refused")
        st, _, _ = b.call("DELETE", "/api/v1/session",
                          headers={"HTTP_ORIGIN": "http://steward.example"})
        check(st == 204, "logout from our own origin")
        st, _, _ = b.call("GET", "/api/v1/session")
        check(st == 401, "session gone after logout")

        # Behind nginx proxy manager: TLS ends at the proxy, which connects from
        # 172.17.0.2 and says so in X-Forwarded-*. The Origin is https.
        npm = {"HTTP_X_FORWARDED_FOR": "6.6.6.6, 203.0.113.50", "HTTP_X_FORWARDED_PROTO": "https",
               "HTTP_X_FORWARDED_PREFIX": "/steward", "HTTP_ORIGIN": "https://steward.example"}
        p = Client(addr, remote="172.17.0.2", extra=npm)
        st, h, _ = p.call("POST", "/api/v1/session", {"username": "STEWARD_ADM", "password": "admin-pass"})
        check(st == 201, "sign in through a trusted proxy with an https Origin")
        check("Path=/steward/api;" in h.get("Set-Cookie", ""), "cookie path follows X-Forwarded-Prefix")
        st, _, doc = p.call("GET", "/api/v1/session")
        check(st == 200 and "SYSPRV" in doc["authorized_privileges"] and "GRPPRV" in doc["authorized_privileges"],
              "privileges above bit 31 are reported (GRPPRV)")
        check("SYSPRV" not in doc["current_privileges"], "authorized-only privileges start switched off (D9)")
        st, _, doc = p.call("PUT", "/api/v1/session/privileges", {"enabled": ["GRPPRV", "SYSPRV"]})
        check(st == 200 and {"GRPPRV", "SYSPRV"} <= set(doc["current_privileges"]) and
              set(doc["enabled_privileges"]) == {"GRPPRV", "SYSPRV"},
              "switching on authorized privileges, including one above bit 31")
        st, _, doc = p.call("PUT", "/api/v1/session/privileges", {"enabled": ["CMKRNL"]})
        check(st == 403 and "CMKRNL" in doc.get("detail", ""), "an unauthorized privilege is refused by name")

        # The same headers from a peer we do not trust are ignored: the https Origin
        # no longer matches what lighttpd saw, so the request is refused.
        spoof = Client(addr, remote="198.51.100.1", extra=npm)
        st, _, _ = spoof.call("POST", "/api/v1/session", {"username": "STEWARD_ADM", "password": "admin-pass"})
        check(st == 403, "forwarded headers from an untrusted peer are not believed")

        st, _, doc = b.call("POST", "/api/v1/session", {"username": "STEWARD_ADMINISTRATOR", "password": "x"})
        check(st == 401, "a username longer than 12 characters fails like a wrong password")

        st, _, doc = b.call("POST", "/api/v1/session", {"username": "EXPIRED", "password": "expired-pass"})
        check(st == 403 and doc["type"].endswith("/password-expired"), "expired password refused")

        st, _, _ = b.call("POST", "/api/v1/session", headers={"CONTENT_TYPE": "text/plain"},
                          body={"username": "x", "password": "y"})
        check(st == 415, "non-JSON bodies refused")

        st, _, _ = b.call("GET", "/api/v1/users/a%2Fb")
        check(st == 404, "unknown endpoints are 404")

        with open(audit.name, "rb") as f:
            raw = f.read()
        check(all(b < 0x80 for b in raw), "the audit log is plain ASCII")
        log = raw.decode("ascii", "replace")
        check('client="203.0.113.50"' in log and 'user="STEWARD_ADM"' in log,
              "audit records the browser's address behind the proxy")
        check('action="privileges" target="SYSPRV,GRPPRV" outcome="ok"' in log,
              "switching privileges on is audited")
        check('outcome="failed" detail="invalid password"' in log,
              "audit records why a login failed (the client is not told)")
        check('user="STEWARD_ADMINISTRATOR"' in log,
              "an over-long username is refused before $ACM and still audited")
        check("test-pass" not in log and "admin-pass" not in log, "no password reaches the audit log")
    finally:
        proc.terminate()
        _, err = proc.communicate(timeout=5)
        os.unlink(audit.name)
    check(b"persona still active" not in err, "no persona leak was detected")
    print("%d checks, %d failed" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "build/steward"))
