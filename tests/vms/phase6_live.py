"""phase6_live.py - Phase 6 on a VMS node: access history through the real dispatcher
and platform (tests/vms/api_probe), checked against ACCOUNTING and the files themselves.

    python3 tests/vms/phase6_live.py [node]      (default x86; run from the repo top)

READ-ONLY: it reads accounting, the audit journal, OpenSSH's logs and a scratch copy
of Steward's audit log ([.BUILD]PROBE_AUDIT.LOG, made with CONVERT/SHARE); it changes
nothing on the node. Needs @BUILD_VMS run there first; the node's paths come from
tools/nodes.conf."""
import json, re, subprocess, sys, time

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
VMS = ["tools/vms.sh", NODE, "dcl"]
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
TOP = WORKDIR[:-1]
SETUP = ['ap = "$' + TOP + '.BUILD]API_PROBE.EXE"',
         "define API_PROBE_AUDIT " + TOP + '.BUILD]PROBE_AUDIT.LOG']

def vms(*cmds):
    return subprocess.run(VMS + list(cmds), capture_output=True, text=True).stdout.replace("\r", "")

def access(user, privs, query):
    t0 = time.time()
    out = vms(*SETUP, 'ap %s %s "/api/v1/access?%s"' % (user, privs, query))
    took = time.time() - t0
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc, took

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

# Steward's own log, as a scratch copy: the pool holds the real one open for writing.
vms("set process/privilege=sysprv",
    "convert/share SYS$SYSDEVICE:[STEWARD_DATA.RUN]AUDIT.LOG " + TOP + ".BUILD]PROBE_AUDIT.LOG")

now = int(time.time())
st, doc, took = access("STEWARD_ADM", "SYSPRV", "since=%d&limit=2000" % (now - 86400))
check(st == 200 and doc and all(s["read"] for s in doc["sources"].values()),
      "with SYSPRV every source is read", (st, doc and doc["sources"]))
# Timed on the node, the output discarded: the round trip here is mostly the transfer.
out = vms(*SETUP, "t0 = f$time()", 'pipe ap STEWARD_ADM SYSPRV "/api/v1/access?since=%d&limit=2000" > NLA0:' % (now - 86400),
          "t1 = f$time()", "write sys$output f$delta_time(t0, t1)")
m = re.search(r"(\d+) (\d\d):(\d\d):(\d\d)\.(\d\d)", out)
secs = (int(m.group(1)) * 86400 + int(m.group(2)) * 3600 + int(m.group(3)) * 60 + int(m.group(4)) + int(m.group(5)) / 100) if m else 99
check(secs < 5, "a day's history in %.2fs on the node (image start-up included)" % secs, out[-200:])
ev = doc["events"] if doc else []
check(all(ev[i]["start"] >= ev[i + 1]["start"] for i in range(len(ev) - 1)), "newest first")
ssh = [e for e in ev if e["route"] == "SSH" and e["kind"] == "session"]
check(ssh and all(e["user"] or e["detail"].startswith("no sign-in") for e in ssh),
      "every SSH connection has its user, or says it never signed in (%d connections)" % len(ssh),
      [e for e in ssh if not e["user"]][:3])
check(any(e["detail"].startswith("publickey") for e in ssh), "the sign-in method, from OpenSSH's logs")

# Against ACCOUNTING: the SSH server's connections that ended between 30 and 5 minutes
# ago, by PID. (ACCOUNTING dates a process by its end; a minute's grace either side
# for the two clocks.)
st, doc, _ = access("STEWARD_ADM", "SYSPRV", "since=%d&until=%d&route=SSH&outcome=session&limit=2000" % (now - 1800, now - 300))
ours = {e["pid"] for e in (doc["events"] if doc else []) if e.get("end") and now - 1740 <= e["end"] <= now - 360}
acct = vms("set process/privilege=sysprv",
           'accounting/since="-0:30"/before="-0:05"/type=process/process=network/user=SSH$SSH')
theirs = set(re.findall(r"PROCESS NETWORK\s+SSH\$SSH\s+([0-9A-F]{8})", acct))
check(ours and ours <= theirs, "SSH connections are ACCOUNTING's SSH$SSH network processes: %d here, all among its %d" % (len(ours), len(theirs)),
      sorted(ours - theirs)[:5])

# A failure is one event, whichever sources saw it.
st, doc, _ = access("STEWARD_ADM", "SYSPRV", "since=%d&outcome=failure&limit=2000" % (now - 86400))
fails = doc["events"] if doc else []
check(all(e["kind"] == "failure" for e in fails), "outcome=failure gives failures only")
# One attempt seen by two sources must be one event. (Several real attempts in the
# same second, from one sign-in each, are several events: four load-test clients
# whose password had expired, 2026-10-11.)
sources = {}
for e in fails:
    sources.setdefault((e["user"], e["from"], e["start"] // 30), set()).add(e["source"])
check(all(len(v) == 1 for v in sources.values()), "no failure is shown twice (by two sources)",
      [k for k, v in sources.items() if len(v) > 1][:3])
check(not any(e["user"].startswith("<") for e in fails), "LOGINOUT's <login> is replaced by the name tried")

st, doc, _ = access("STEWARD_TEST", "-", "since=%d" % (now - 3600))
src = doc["sources"] if doc else {}
check(st == 200 and src.get("live", {}).get("read") and
      all(not src[k]["read"] and src[k].get("vms_message", "").startswith("%RMS-") for k in ("accounting", "audit", "ssh", "steward")),
      "STEWARD_TEST (no privileges): each file refused by OpenVMS, by name; the live list still read", src)
check(doc is not None and all(e["user"] in ("STEWARD_TEST", "") for e in doc["events"]),
      "and only its own processes", doc and doc["events"][:3])

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
