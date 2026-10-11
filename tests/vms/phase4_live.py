"""phase4_live.py - Phase 4 on a VMS node: create, copy and delete users through the
real dispatcher and platform (tests/vms/api_probe), as STEWARD_ADM's persona with
SYSPRV switched on, each checked against AUTHORIZE, and everything removed again.

    python3 tests/vms/phase4_live.py [node]      (default x86; run from the repo top)

CHANGES THE NODE: creates and deletes only STEWARD_NEW ([362,10]) and STEWARD_COPY
([362,11]), the names the user approved for Phase 4, and creates then removes the
directory SYS$SYSDEVICE:[STEWARD_NEW]. Refuses to run if either account exists. Needs
@BUILD_VMS run on the node first; the node's paths come from tools/nodes.conf."""
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
    out = subprocess.run(VMS + [AP, "ap " + " ".join(args)], capture_output=True, text=True).stdout
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
    return subprocess.run(VMS + ["mcr authorize " + cmd], capture_output=True, text=True).stdout

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

A = ("STEWARD_ADM", "SYSPRV")
for u in ("STEWARD_NEW", "STEWARD_COPY"):
    if "Username:" in authorize("show " + u):
        sys.exit("phase4_live: %s exists; remove it first" % u)

st, _, doc = api(*A, "/api/v1/uic/next?group=362")
check(st == 200 and doc["uic"] == "[362,4]", "next free member of group 362 (1-3 in use)", (st, doc))

st, _, doc = api("STEWARD_TEST", "-", "/api/v1/users", "POST",
                 {"username": "steward_new", "uic": "[362,10]", "password": "PHASE4_NEW_ACCOUNT_PW1"})
check(st == 403, "STEWARD_TEST cannot create a user: OpenVMS refuses", (st, doc))
st, _, doc = api("STEWARD_ADM", "-", "/api/v1/users", "POST",
                 {"username": "steward_new", "uic": "[362,10]", "password": "PHASE4_NEW_ACCOUNT_PW1"})
check(st == 403, "nor STEWARD_ADM without SYSPRV switched on", (st, doc))

# OpenVMS refuses this password (no PWDMIX: A-Z 0-9 $ _ only), after the record was
# written: the create must undo itself and leave nothing.
st, _, doc = api(*A, "/api/v1/users", "POST",
                 {"username": "steward_new", "uic": "[362,10]", "password": "Not-a-legal-password"})
check(st == 422 and "PWDSYNTAX" in str(doc), "a password OpenVMS refuses (PWDSYNTAX) fails the create", (st, doc))
check("no user matches" in authorize("show steward_new").lower() and "NOSUCHID" in authorize("show/identifier steward_new"),
      "and leaves nothing behind: no record, no identifier")

before_default = authorize("show default")
st, _, doc = api(*A, "/api/v1/users", "POST",
                 {"username": "steward_new", "uic": "[362,10]", "password": "PHASE4_NEW_ACCOUNT_PW1",
                  "owner": "phase4 new", "flags": [], "default_device": "SYS$SYSDEVICE:",
                  "default_directory": "[STEWARD_NEW]", "create_directory": True})
check(st == 201 and doc["username"] == "STEWARD_NEW" and doc["uic"] == "[362,10]", "create STEWARD_NEW from DEFAULT", (st, doc))
show = authorize("show steward_new")
check("Owner:  phase4 new" in show and "UIC:    [362,10]" in show, "AUTHORIZE: owner and UIC")
check(re.search(r"Flags:\s*$", show, re.M) is not None, "AUTHORIZE: DISUSER cleared, as asked", re.findall(r"Flags:.*", show))
check("Default:  SYS$SYSDEVICE:[STEWARD_NEW]" in show or "Default:  [STEWARD_NEW]" in show, "AUTHORIZE: default directory", re.findall(r"Default:.*", show))
check("Pwdchange:      (pre-expired)" in show, "AUTHORIZE: password pre-expired")
# Quotas and password policy, without the login-failure count on the same line.
policy = lambda t: re.findall(r"(?:Maxjobs|Fillm|Bytlm|Prclm|Prio|WSquo|Pgflquo)[^\n]*|Pwdminimum:\s*\d+|Pwdlifetime:\s*\S+", t)
check(policy(show) == policy(before_default), "AUTHORIZE: quotas and password policy as DEFAULT's")
check("STEWARD_NEW" in authorize("show/identifier steward_new"), "AUTHORIZE: UIC identifier added")
d = subprocess.run(VMS + ["dir/owner/nohead/notrail SYS$SYSDEVICE:[000000]STEWARD_NEW.DIR"], capture_output=True, text=True).stdout
check("STEWARD_NEW" in d and "[STEWARD_NEW]" in d.replace("[362,10]", "[STEWARD_NEW]"), "home directory created, owned by the new user", d)

st, _, doc = api(*A, "/api/v1/users", "POST",
                 {"username": "steward_copy", "uic": "[362,11]", "password": "PHASE4_COPY_ACCOUNT_PW1",
                  "template": "steward_test"})
check(st == 201 and doc["owner"] == "steward probe", "copy STEWARD_TEST to STEWARD_COPY", (st, doc))
show = authorize("show steward_copy")
check("Default:  SYS$SYSDEVICE:[STEWARD_TEST]" in show, "AUTHORIZE: the source's fields, directory included (as AUTHORIZE COPY)")
st, _, doc = api(*A, "/api/v1/users", "POST",
                 {"username": "steward_copy", "uic": "[362,12]", "password": "PHASE4_COPY_ACCOUNT_PW1"})
check(st == 409, "an existing username is refused", (st, doc))

for u in ("STEWARD_NEW", "STEWARD_COPY"):
    st, et, doc = api(*A, "/api/v1/users/" + u)
    st, _, doc = api(*A, "/api/v1/users/" + u, "DELETE", None, et)
    check(st == 204, "delete " + u, (st, doc))
    check("no user matches" in authorize("show " + u).lower() or "BADSPC" in authorize("show " + u), "AUTHORIZE: %s gone" % u)
    check("NOSUCHID" in authorize("show/identifier " + u), "AUTHORIZE: %s's UIC identifier gone" % u)

# The directory stays, as with AUTHORIZE REMOVE: remove the empty test directory.
subprocess.run(VMS + ["set security/protection=(o:rwed) SYS$SYSDEVICE:[000000]STEWARD_NEW.DIR",
                      "delete/nolog SYS$SYSDEVICE:[000000]STEWARD_NEW.DIR;"], capture_output=True, text=True)
d = subprocess.run(VMS + ["dir/nohead/notrail SYS$SYSDEVICE:[000000]STEWARD_NEW.DIR"], capture_output=True, text=True).stdout
check("STEWARD_NEW.DIR" not in d, "test directory removed")
print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
