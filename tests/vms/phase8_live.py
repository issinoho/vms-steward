"""phase8_live.py - Phase 8 (8a) on a VMS node: processes through the real dispatcher
and platform (tests/vms/api_probe), checked against DCL's F$PID and F$GETJPI.

    python3 tests/vms/phase8_live.py [node]      (default x86; run from the repo top)

READ-ONLY. STEWARD_ADM needs GROUP and WORLD authorized (the user agreed, 2026-10-15).
The reference list comes from tests/vms/phase8_jpi.com, run by the work account, which
sees every process. Processes come and go between the two reads (the ssh sessions
tools/vms.sh opens, the work account's own), so those are left out of the
comparison."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    fields = next(l.split() for l in f if l.split() and l.split()[0] == NODE)
WORKDIR, ME = fields[5], fields[4].upper()
AP = 'ap = "$' + WORKDIR[:-1] + '.BUILD]API_PROBE.EXE"'
TRANSIENT = {"SSH$SSH", ME}

def vms(*cmds):
    return subprocess.run(["tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path):
    out = vms(AP, 'ap %s %s "%s"' % (user, privs, path))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def dcl_procs():
    out = subprocess.run(["tools/vms.sh", NODE, "run", "tests/vms/phase8_jpi.com"], stdout=subprocess.PIPE,
                         encoding="latin-1").stdout.replace("\r", "")
    procs = {}
    for l in out.splitlines():
        p = l.split("|")
        if len(p) == 7 and p[0] == "P":
            g, m = (int(x) for x in p[4].split(","))
            procs[p[1]] = {"name": p[2], "username": p[3], "uic": "[%o,%o]" % (g, m), "prib": int(p[5] or 0), "image": p[6]}
    return procs

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

def stable(procs):
    return {pid: p for pid, p in procs.items() if p["username"].upper() not in TRANSIENT}

ref = dcl_procs()
check(len(ref) > 20, "DCL lists %d processes" % len(ref))
pool = sorted(pid for pid, p in ref.items() if p["name"].startswith("STEWARD_19"))
group = ref[pool[0]]["uic"].strip("[]").split(",")[0] if pool else None

st, doc = api("STEWARD_TEST", "-", "/api/v1/processes")
check(st == 200 and doc["processes"] == [],
      "STEWARD_TEST, nothing switched on: none (its only process is the one serving the request)", (st, doc))

st, doc = api("STEWARD_ADM", "WORLD", "/api/v1/processes")
ours = {p["pid"]: p for p in (doc or {}).get("processes", [])}
a, b = stable(ours), stable(ref)
diff = set(a) ^ set(b)
check(st == 200 and len(a) > 20 and len(diff) <= 2,
      "with WORLD: the same processes as DCL, %d here, %d there" % (len(a), len(b)), sorted(diff))
same = [pid for pid in set(a) & set(b)
        if (a[pid]["name"], a[pid]["username"], a[pid]["uic"], a[pid]["base_priority"]) ==
           (b[pid]["name"], b[pid]["username"], b[pid]["uic"], b[pid]["prib"])]
check(len(same) >= len(set(a) & set(b)) - 1,
      "and each with DCL's name, username, UIC and base priority (%d of %d)" % (len(same), len(set(a) & set(b))),
      [(pid, a[pid], b[pid]) for pid in (set(a) & set(b)) - set(same)][:3])

st, doc = api("STEWARD_ADM", "GROUP", "/api/v1/processes")
ours = {p["pid"] for p in (doc or {}).get("processes", [])}
check(st == 200 and set(pool) <= ours and all(p["uic"].startswith("[%s," % group) for p in doc["processes"]),
      "with GROUP: only group %s's, Steward's pool among them" % group, (st, sorted(ours)))
st, doc = api("STEWARD_ADM", "-", "/api/v1/processes")
check(st == 200 and doc["processes"] == [], "without GROUP or WORLD: none", (st, doc))

st, doc = api("STEWARD_ADM", "GROUP", "/api/v1/processes/" + pool[0])
r = ref[pool[0]]
check(st == 200 and doc["name"] == r["name"] and doc["username"] == r["username"] and
      doc["kind"] == "detached" and doc["quotas"]["astlm"]["limit"] > 0 and doc["image"].upper().endswith(r["image"].upper()[-20:]),
      "one process: Steward's pool process as F$GETJPI gives it", (st, doc and {k: doc[k] for k in ("name", "username", "kind", "image")}))
check(st == 200 and doc["current_privileges"] == ["IMPERSONATE", "TMPMBX", "NETMBX"],
      "its privileges as STEWARD$CONTROL STATUS shows them (DETACH, TMPMBX, NETMBX)", doc and doc.get("current_privileges"))
st, doc = api("STEWARD_TEST", "-", "/api/v1/processes/" + pool[0])
check(st == 403 and "NOPRIV" in json.dumps(doc), "STEWARD_TEST may not see it: NOPRIV, as SHOW PROCESS/ID", (st, doc))
st, doc = api("STEWARD_TEST", "-", "/api/v1/processes/0000FFF0")
check(st == 404 and "NONEXPR" in json.dumps(doc), "no such process: NONEXPR", (st, doc))

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
