"""phase10_live.py - Phase 10 on a VMS node: system parameters through the real
dispatcher and platform (tests/vms/api_probe), checked against SYSGEN SHOW/ALL.

    python3 tests/vms/phase10_live.py [node]      (default x86; run from the repo top)

READ-ONLY. With PHASE10_HELPER unset it stages vms/steward_sysgen.com under
[STEWARD_TEST.P10T] (the helper runs as STEWARD_TEST, who must read it) and removes it
after; with PHASE10_HELPER=installed it uses STEWARD$ROOT:[COM]STEWARD_SYSGEN.COM. The
reference listing is SYSGEN SHOW/ALL written to a file by the work account, read with
a parser of the test's own."""
import json, os, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P10T]"
INSTALLED = os.environ.get("PHASE10_HELPER") == "installed"
HELPER = None if INSTALLED else STAGE + "STEWARD_SYSGEN.COM"

def vms(*cmds):
    return subprocess.run(["timeout", "180", "tools/vms.sh", NODE, "dcl"] + list(cmds), capture_output=True,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path):
    pre = ['define/nolog API_PROBE_SYSGEN_HELPER "%s"' % HELPER] if HELPER else []
    out = vms(*([AP] + pre + ['ap %s %s "%s"' % (user, privs, path)]))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def reference():
    """SYSGEN SHOW/ALL by the work account: {name: current}, by whitespace tokens and
    quotes, independently of st_sysgen.c."""
    vms('open/write f [.BUILD]P10L_SHOW.COM', 'write f "$ mcr sysgen"', 'write f "SET/OUTPUT=[.BUILD]P10L_SHOW.TXT"',
        'write f "SHOW/ALL"', 'close f', '@[.BUILD]P10L_SHOW.COM')
    local = "/tmp/p10l_show_%d.txt" % os.getpid()
    subprocess.run(["timeout", "120", "tools/vms.sh", NODE, "get", "BUILD/P10L_SHOW.TXT", local], capture_output=True)
    vms("delete/nolog [.BUILD]P10L_SHOW.*;*")
    ref = {}
    with open(local, encoding="latin-1") as f:
        for l in f.read().replace("\r", "").split("\n"):
            m = re.match(r'^([A-Z0-9_$]+)\s+("[^"]*"|\(none set\)|\S+)', l)
            if m and not l.startswith("Parameter"):
                ref[m.group(1)] = m.group(2).strip('"').rstrip()
    os.remove(local)
    return ref

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

try:
    if HELPER:
        vms("create/directory/protection=(S:RWED,O:RWED,G:RE,W:RE) " + STAGE,
            "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P10T.DIR",
            "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_sysgen.com " + STAGE)
    ref = reference()
    check(len(ref) > 250, "SYSGEN SHOW/ALL lists %d parameters" % len(ref))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/sysgen")
    ours = {p["name"]: p for p in (doc or {}).get("parameters", [])}
    check(st == 200 and set(ours) == set(ref), "STEWARD_TEST: the same parameters (%d)" % len(ours),
          (st, sorted(set(ours) ^ set(ref))[:6], doc if st != 200 else ""))
    diff = [n for n in set(ours) & set(ref) if ours[n]["current"] != ref[n]]
    check(len(diff) <= 2, "each with SYSGEN's current value (%d differ)" % len(diff),
          [(n, ours[n]["current"], ref[n]) for n in diff[:5]])
    p = ours.get("SCSNODE")
    check(p and p["ascii"] and p["current"] == ref.get("SCSNODE"), "SCSNODE, a string, as SYSGEN shows it", p)
    p = ours.get("GBLPAGES")
    check(p and p["dynamic"] and "internal" in p and p["unit"] == "Pagelets", "GBLPAGES: dynamic, its unit, its internal value", p)
    st, doc = api("STEWARD_TEST", "-", "/api/v1/sysgen?filter=MAXSYS*")
    names = [p["name"] for p in (doc or {}).get("parameters", [])]
    check(st == 200 and names == ["MAXSYSGROUP"], "filtered by a pattern", names)
    left = vms('pipe show system | search sys$pipe "STW"')
    check("STW" not in left.replace("search sys$pipe", ""), "no helper process left behind", left[-200:])
finally:
    if HELPER:
        vms("set security/protection=(S:RWED,O:RWED) %s*.*;*" % STAGE, "delete/nolog %s*.*;*" % STAGE,
            "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P10T.DIR",
            "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P10T.DIR;*")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
