"""phase3_live.py - Phase 3 on a VMS node: changes through the real dispatcher and
platform (tests/vms/api_probe), as STEWARD_ADM's persona with SYSPRV switched on (D9),
each checked against AUTHORIZE, and everything put back.

    python3 tests/vms/phase3_live.py [node]      (default x86; run from the repo top)

CHANGES THE NODE: only STEWARD_TEST (restored, then compared with AUTHORIZE's own
output from before) and STEWARD_TEST_ID (created, then deleted), the two names the
user approved for Phase 3 testing. Needs @BUILD_VMS run on the node first, and a work
account that may create personas. The node's paths come from tools/nodes.conf."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
VMS = ["tools/vms.sh", NODE, "dcl"]
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
AP = 'ap = "$' + WORKDIR[:-1] + '.BUILD]API_PROBE.EXE"'

def q(s):
    return '"' + s.replace('"', '""') + '"'

def api(user, privs, path, method="GET", body=None, etag=None):
    # Every argument quoted: a bare "-" at the end of a DCL line is a continuation.
    args = [user, privs, q(path), method, q(json.dumps(body)) if body is not None else q("-")]
    if etag:
        args.append(q(etag))
    out = subprocess.run(VMS + [AP, "ap " + " ".join(args)], stdout=subprocess.PIPE, text=True).stdout
    lines = [l for l in out.splitlines() if l.strip()]
    for i, l in enumerate(lines):
        m = re.match(r"^(\d{3}) (?:ETag=(\S+) )?$", l + " ") or re.match(r"^(\d{3})(?: ETag=(\S+))?\s*$", l)
        if m:
            st = int(m.group(1))
            rest = lines[i + 1] if i + 1 < len(lines) else ""
            try:
                doc = json.loads(rest) if rest.startswith("{") else None
            except ValueError:
                doc = None
            return st, m.group(2), doc
    return None, None, out

def authorize(cmd):
    return subprocess.run(VMS + ["mcr authorize " + cmd], stdout=subprocess.PIPE, text=True).stdout

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

A = ("STEWARD_ADM", "SYSPRV")
authorize_before = authorize("show steward_test")

st, et, before = api(*A, "/api/v1/users/STEWARD_TEST")
check(st == 200 and et, "GET STEWARD_TEST with an ETag", (st, et))
orig = {k: before[k] for k in ("owner", "flags", "quotas", "secondary_days", "restricted_hours")}

st, _, doc = api("STEWARD_ADM", "-", "/api/v1/users/STEWARD_TEST", "PATCH", {"owner": "x"}, et)
check(st == 403, "without SYSPRV switched on, OpenVMS refuses the change", (st, doc))

st, _, doc = api("STEWARD_TEST", "-", "/api/v1/users/STEWARD_TEST", "PATCH", {"owner": "x"}, et)
check(st == 403, "STEWARD_TEST cannot change its own record", (st, doc))

change = {"owner": "steward probe (phase 3)", "flags": ["DISWELCOME", "DISNEWMAIL"],
          "quotas": {"prio": 5, "wsextent": 20000}, "secondary_days": ["SAT"],
          "restricted_hours": {"batch": {"primary": [0, 1, 2, 3], "secondary": [22, 23]}}}
st, et2, doc = api(*A, "/api/v1/users/STEWARD_TEST", "PATCH", change, et)
check(st == 200 and et2 and et2 != et and doc["owner"] == change["owner"], "PATCH as STEWARD_ADM with SYSPRV", (st, doc))
show = authorize("show steward_test")
check("Owner:  steward probe (phase 3)" in show, "AUTHORIZE: owner changed")
check(re.search(r"Flags:\s+DisWelcome DisNewMail", show) is not None, "AUTHORIZE: flags DisWelcome DisNewMail", re.findall(r"Flags:.*", show))
check(re.search(r"Prio:\s+5\b", show) and re.search(r"WSextent:\s+20000\b", show), "AUTHORIZE: Prio 5, WSextent 20000")
check(re.search(r"Primary days:\s+Mon\s+Tue\s+Wed\s+Thu\s+Fri\s+Sun", show) is not None, "AUTHORIZE: Sunday is now a primary day", re.findall(r"Primary days:.*", show))
check(re.search(r"Batch:\s+----#{20}\s+#{22}--", show) is not None, "AUTHORIZE: batch hours 0-3 primary, 22-23 secondary refused", re.findall(r"Batch:.*", show))

st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST", "PATCH", {"owner": "late"}, et)
check(st == 412, "the old ETag is refused after the change")

st, et3, doc = api(*A, "/api/v1/users/STEWARD_TEST", "PATCH", orig, et2)
check(st == 200 and doc["owner"] == orig["owner"] and doc["flags"] == orig["flags"] and
      doc["quotas"] == orig["quotas"], "restore STEWARD_TEST", (st, doc and doc.get("owner")))
show2 = authorize("show steward_test")
strip = lambda s: re.sub(r"Last Login:.*|Login Fails:.*|Pwdchange:.*", "", s)
check(strip(show2).split() == strip(authorize_before).split(), "AUTHORIZE: STEWARD_TEST exactly as before (apart from login times)")

# ---- identifiers
st, _, doc = api(*A, "/api/v1/identifiers", "POST", {"name": "STEWARD_TEST_ID", "attributes": ["RESOURCE"]})
check(st == 201 and doc["attributes"] == ["RESOURCE"], "create STEWARD_TEST_ID", (st, doc))
val = doc and doc.get("value")
st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST/identifiers", "POST", {"name": "STEWARD_TEST_ID", "attributes": ["RESOURCE"]})
check(st == 201 and any(i["name"] == "STEWARD_TEST_ID" and i["attributes"] == ["RESOURCE"] for i in doc["identifiers"]),
      "grant it to STEWARD_TEST with RESOURCE", (st, doc))
show = authorize("show/identifier/full STEWARD_TEST_ID")
check("STEWARD_TEST_ID" in show and val in show and re.search(r"STEWARD_TEST\s+RESOURCE", show), "AUTHORIZE: identifier, value, holder with RESOURCE", show)
st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST/identifiers/STEWARD_TEST_ID", "PUT", {"attributes": []})
check(st == 200 and any(i["name"] == "STEWARD_TEST_ID" and i["attributes"] == [] for i in doc["identifiers"]), "clear the holding's RESOURCE")
st, _, doc = api(*A, "/api/v1/identifiers/STEWARD_TEST_ID", "PATCH", {"name": "STEWARD_TEST_ID2", "attributes": ["NOACCESS"]})
check(st == 200 and doc["name"] == "STEWARD_TEST_ID2" and doc["attributes"] == ["NOACCESS"], "rename, replace attributes", (st, doc))
show = authorize("show/identifier/full STEWARD_TEST_ID2")
check("STEWARD_TEST_ID2" in show and "NOACCESS" in show, "AUTHORIZE: renamed, NOACCESS", show)
st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST/identifiers/STEWARD_TEST_ID2", "DELETE")
check(st == 204, "revoke", (st, doc))
st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST/identifiers", "POST", {"name": "STEWARD_TEST_ID2"})
check(st == 201, "grant again (for the delete-while-held check)")
st, _, doc = api(*A, "/api/v1/identifiers/STEWARD_TEST_ID2", "DELETE")
check(st == 204, "delete the identifier while held", (st, doc))
show = authorize("show/identifier STEWARD_TEST_ID2")
check("STEWARD_TEST_ID2" not in show.replace("show/identifier STEWARD_TEST_ID2", ""), "AUTHORIZE: identifier gone", show)
st, _, doc = api(*A, "/api/v1/users/STEWARD_TEST/identifiers")
check(st == 200 and doc["identifiers"] == [], "STEWARD_TEST holds nothing again", doc)
print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
