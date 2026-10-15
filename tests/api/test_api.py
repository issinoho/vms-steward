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

        # Phase 2: users and identifiers, read as the persona. SYSPRV is still on.
        st, _, doc = p.call("GET", "/api/v1/users?filter=STEWARD*&limit=1")
        check(st == 200 and [u["username"] for u in doc["users"]] == ["STEWARD_ADM"] and
              doc["next"] == "STEWARD_ADM", "list users: wildcard filter, one page, cursor")
        st, _, doc = p.call("GET", "/api/v1/users?filter=STEWARD*&after=STEWARD_ADM")
        check(st == 200 and [u["username"] for u in doc["users"]] == ["STEWARD_TEST"] and doc["next"] is None,
              "the next page, and the end")
        st, _, doc = p.call("GET", "/api/v1/users/steward_test")
        check(st == 200 and doc["restricted_hours"]["dialup"]["primary"] == list(range(24)) and
              doc["secondary_days"] == ["SAT", "SUN"] and doc["password"]["minimum_length"] == 15,
              "user detail: access hours, days, password policy")
        st, _, doc = p.call("GET", "/api/v1/users/STEWARD_TEST/identifiers")
        check(st == 200 and [i["name"] for i in doc["identifiers"]] == ["STEWARD_OPS"], "identifiers held")
        st, _, doc = p.call("GET", "/api/v1/identifiers?filter=steward*")
        check(st == 200 and [i["name"] for i in doc["identifiers"]] == ["STEWARD_DEMO", "STEWARD_OPS"],
              "identifiers, filtered and sorted")
        st, _, doc = p.call("GET", "/api/v1/identifiers/STEWARD_OPS/holders")
        check(st == 200 and {x["username"] for x in doc["holders"]} == {"STEWARD_ADM", "STEWARD_TEST"},
              "holders")
        st, _, _ = p.call("GET", "/api/v1/users?filter=%22%3Cscript%3E")
        check(st == 400, "a filter with a quote is refused, not echoed")
        st, _, _ = p.call("PUT", "/api/v1/session/privileges", {"enabled": []})
        st, _, doc = p.call("GET", "/api/v1/users")
        check(st == 403 and doc.get("vms_status") == "%X0001829A",
              "with SYSPRV switched off again, the OS refuses the list (RMS-E-PRV, as on the node)")

        # Phase 3: a password set and a password change; neither may reach the log.
        p.call("PUT", "/api/v1/session/privileges", {"enabled": ["SYSPRV"]})
        st, _, _ = p.call("POST", "/api/v1/users/EXPIRED/password",
                          {"password": "Phase3-admin-set-pw", "pre_expired": True})
        check(st == 204, "an administrator sets a password")
        st, _, doc = p.call("POST", "/api/v1/session/password",
                            {"username": "EXPIRED", "current": "Phase3-admin-set-pw", "new": "Phase3-user-chosen-pw"})
        check(st == 204, "the user changes it, without being signed in")
        st, _, doc = p.call("GET", "/api/v1/users/EXPIRED")
        etag = doc.get("etag")
        st, h, doc = p.call("PATCH", "/api/v1/users/EXPIRED", {"owner": "edited"},
                            headers={"HTTP_IF_MATCH": etag})
        check(st == 200 and doc["owner"] == "edited" and h.get("ETag") not in (None, etag),
              "PATCH with If-Match, through FastCGI, returns the new ETag")
        # Phase 4: create and delete; the new account's password must not reach the log.
        st, _, doc = p.call("POST", "/api/v1/users", {"username": "API_NEW", "uic": "[362,20]",
                                                      "password": "Phase4-create-pw", "flags": []})
        check(st == 201 and doc["username"] == "API_NEW", "create a user through FastCGI")
        st, h, doc = p.call("GET", "/api/v1/users/API_NEW")
        st, _, _ = p.call("DELETE", "/api/v1/users/API_NEW", headers={"HTTP_IF_MATCH": h.get("ETag")})
        check(st == 204, "and delete it")
        st, _, _ = p.call("POST", "/api/v1/users/EXPIRED/password",   # the fixture back, for later checks
                          {"password": "expired-pass", "pre_expired": True})
        check(st == 204, "fixture restored")
        # Phase 7b: define and deassign; the equivalence must not reach the log (D15).
        p.call("PUT", "/api/v1/session/privileges", {"enabled": ["SYSPRV", "SYSNAM"]})
        st, _, doc = p.call("PUT", "/api/v1/logical", {"table": "LNM$SYSTEM_TABLE", "name": "API_7B", "mode": "exec",
                                                       "equivalences": [{"value": "Phase7b-equivalence"}]})
        check(st == 201 and doc["modes"] == ["exec"], "define a logical name through FastCGI")
        st, _, doc = p.call("DELETE", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=API_7B&mode=exec")
        check(st == 200 and doc["removed"] == ["exec"], "and deassign it")
        # Phase 8b: a stop is audited; Steward's own pool is refused and audited too.
        p.call("PUT", "/api/v1/session/privileges", {"enabled": ["WORLD"]})
        st, _, _ = p.call("DELETE", "/api/v1/processes/00007500")
        check(st == 409, "Steward's own pool process cannot be stopped through Steward")
        st, _, doc = p.call("DELETE", "/api/v1/processes/00007530")
        check(st == 202 and doc["stopping"], "stop a process through FastCGI")
        p.call("PUT", "/api/v1/session/privileges", {"enabled": []})

        # Phase 9b: queue changes are audited, refusals included.
        st, _, _ = p.call("POST", "/api/v1/queues/SYS$BATCH/stop")
        check(st == 409, "Steward's start-up queue cannot be stopped through Steward")
        st, _, doc = p.call("POST", "/api/v1/jobs/272/hold")
        check(st == 200 and doc["done"] == "held", "hold one's own job through FastCGI")

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

        st, _, _ = b.call("GET", "/api/v1/nope")
        check(st == 404, "unknown endpoints are 404")
        st, _, _ = b.call("GET", "/api/v1/users/a%2Fb")
        check(st == 400, "an encoded slash in a path segment is refused")

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
        check('action="logical-define" target="LNM$SYSTEM_TABLE API_7B exec" outcome="ok"' in log and
              'action="logical-deassign" target="LNM$SYSTEM_TABLE API_7B exec" outcome="ok"' in log and
              "Phase7b-" not in log, "a define and a deassign are audited, without the equivalence")
        check('action="process-stop" target="00007530 \\"WEBMASTER\\" WEBMASTER" outcome="ok"' in log and
              'action="process-stop" target="00007500 \\"STEWARD_19300\\" STEWARD" outcome="refused"' in log,
              "stops and refused stops are audited")
        check('action="queue-stop" target="SYS$BATCH" outcome="refused"' in log and
              'action="job-hold" target="272 \\"REPORT\\" STEWARD_ADM" outcome="ok"' in log,
              "queue and job changes are audited")
        check("test-pass" not in log and "admin-pass" not in log and "Phase3-" not in log and "Phase4-" not in log and "expired-pass" not in log,
              "no password reaches the audit log (sign-in, set, change)")
        check('action="password-set" target="EXPIRED" outcome="ok" detail="pre-expired"' in log and
              'action="password-change" target="EXPIRED" outcome="ok"' in log and
              'action="user-modify" target="EXPIRED" outcome="ok" detail="owner"' in log and
              'action="user-create" target="API_NEW" outcome="ok"' in log and
              'action="user-delete" target="API_NEW" outcome="ok"' in log,
              "the changes are audited")
    finally:
        proc.terminate()
        _, err = proc.communicate(timeout=5)
        os.unlink(audit.name)
    check(b"persona still active" not in err, "no persona leak was detected")
    print("%d checks, %d failed" % (checks, failures))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "build/steward"))
