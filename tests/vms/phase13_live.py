"""phase13_live.py - Phase 13 on a VMS node: monitoring through the real dispatcher and
platform (tests/vms/api_probe), checked against MONITOR and the system itself.

    python3 tests/vms/phase13_live.py [node]      (default x86; run from the repo top)

READ-ONLY. Takes a reading as STEWARD_TEST, runs MONITOR MODES,SYSTEM,IO/SUMMARY for
20 seconds, and takes another: the rates between the two readings (as the page works
them out, www/js/rates.js) must agree with MONITOR's averages over a window inside
theirs (all three in one session), within what a busier or quieter moment can
explain. Also: the mode counters
add up to the CPUs' ticks; the counters only go up; each disk the dashboard lists has
its operation count; and processes are shown only as $GETJPI lets the viewer see them
(STEWARD_TEST its own; STEWARD_ADM everyone's with WORLD)."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
OFF = "set process/privilege=(noall,tmpmbx,netmbx)"

def vms(*cmds, timeout=300):
    return subprocess.run(["timeout", str(timeout), "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
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

def doc_of(text):
    m = re.search(r"^(\d{3})\s*$", text, re.M)
    body = text[m.end():].replace("\n", "") if m else ""
    try:
        return (int(m.group(1)) if m else None), (json.loads(body[body.index("{"):]) if "{" in body else None)
    except ValueError:
        return (int(m.group(1)) if m else None), None

def window(user, privs):
    """A reading, MONITOR MODES,SYSTEM,IO/SUMMARY for 20 s (long enough that
    starting the images either side matters little), another reading: in one
    session, so the readings' window is MONITOR's and a little more. MONITOR's AVE
    column by its row names, and the two readings."""
    out = vms(AP, 'ap %s %s "/api/v1/monitor"' % (user, privs), 'write sys$output "==MON=="',
              'monitor modes,system,io/nodisplay/summary=sys$scratch:p13.sum/interval=5/ending="+00:00:20"',
              "type sys$scratch:p13.sum", "delete/nolog sys$scratch:p13.sum;*", 'write sys$output "==B=="',
              'ap %s %s "/api/v1/monitor"' % (user, privs))
    first, rest = (out.split("==MON==", 1) + [""])[:2]
    mon, second = (rest.split("==B==", 1) + [""])[:2]
    ave = {}
    for line in mon.split("\n"):
        m = re.match(r"^\s{4}(\S.*?\S)\s{2,}([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s+([-\d.]+)\s*$", line)
        if m:
            ave.setdefault(m.group(1), float(m.group(3)))
    return doc_of(first), ave, doc_of(second)

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

WRAP = 2 ** 32
def d32(a, b):
    return b - a if b >= a else (b + WRAP - a if a >= 2 ** 31 and b < 2 ** 31 else None)

(st, a), ave, (st2, b) = window("STEWARD_TEST", "-")
check(st == 200 and st2 == 200 and a and b, "STEWARD_TEST reads the counters, twice (no privilege)", (st, st2))
a = a or {}; b = b or {}
ref = vms(OFF, 'write sys$output "REF|", f$getsyi("ACTIVECPU_CNT"), "|", f$getsyi("MEMSIZE"), "|", f$getsyi("PAGE_SIZE")')
m = re.search(r"REF\|(\d+)\|(\d+)\|(\d+)", ref)
cpus, memsize, pagesize = (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, 0, 0)
check(b.get("cpus") == cpus and b.get("memory", {}).get("total") == memsize * pagesize,
      "CPUs and memory as F$GETSYI gives them (%d CPUs, %d pages of %d)" % (cpus, memsize, pagesize),
      (b.get("cpus"), b.get("memory")))

dt = (b.get("sampled_at_ms", 0) - a.get("sampled_at_ms", 0)) / 1000.0
check(20 < dt < 35, "the readings %.1f s apart, round MONITOR's 20 s" % dt)
if dt > 0 and a.get("modes") and b.get("modes"):
    ticks = sum(b["modes"][k] - a["modes"][k] for k in b["modes"])
    cap = 100 * cpus * dt
    check(abs(ticks / cap - 1) < 0.1, "the mode counters' changes add up to the CPUs' ticks (%d of %d)" % (ticks, cap))
    idle = 100.0 * (b["modes"]["idle"] - a["modes"]["idle"]) / (100 * dt)   # MONITOR's unit: percent summed over CPUs
    check("Idle Time" in ave and abs(idle - ave["Idle Time"]) < 15,
          "idle time %.1f against MONITOR's %.1f (percent, summed over CPUs)" % (idle, ave.get("Idle Time", -1)))
    bio = d32(a["counters"]["buffered_io"], b["counters"]["buffered_io"]) / dt
    check("Buffered I/O Rate" in ave and abs(bio - ave["Buffered I/O Rate"]) <= 0.5 * ave["Buffered I/O Rate"] + 10,
          "buffered I/O %.1f/s against MONITOR's %.1f" % (bio, ave.get("Buffered I/O Rate", -1)))
    faults = d32(a["counters"]["page_faults"], b["counters"]["page_faults"]) / dt
    check("Page Fault Rate" in ave and abs(faults - ave["Page Fault Rate"]) <= 0.5 * ave["Page Fault Rate"] + 20,
          "page faults %.1f/s against MONITOR's %.1f" % (faults, ave.get("Page Fault Rate", -1)))
    free = b["memory"]["free"] / pagesize if pagesize else 0
    check("Free List Size" in ave and abs(free - ave["Free List Size"]) <= 0.02 * ave["Free List Size"] + 500,
          "free list %d pages against MONITOR's %d" % (free, ave.get("Free List Size", -1)))
    procs = b.get("processes", 0)
    # The state counts and RMI$_PROCS do not quite agree, in MONITOR too (NOTES.md).
    check("Process Count" in ave and abs(procs - ave["Process Count"]) <= 3 and abs(sum(b["states"].values()) - procs) <= max(6, procs // 20),
          "%d processes against MONITOR's %d; the states add up to them (%d)" % (procs, ave.get("Process Count", -1), sum(b["states"].values())))
    went_back = [k for k in b["counters"] if d32(a["counters"][k], b["counters"][k]) is None]
    went_back += [k for k in b["modes"] if k != "interrupt" and b["modes"][k] < a["modes"][k]]
    check(not went_back, "every counter went up (or wrapped)", went_back)
    print("INFO interrupt: %d then %d (negative on the VM, NOTES.md)" % (a["modes"]["interrupt"], b["modes"]["interrupt"]))

st, sysdoc = api("STEWARD_TEST", "-", "/api/v1/system")
sysdisks = [d["device"] for d in (sysdoc or {}).get("disks", [])]
mondisks = b.get("disks", [])
ops = [d["operations"] for d in mondisks]
dka = vms(OFF, 'write sys$output "OPS|", f$getdvi("%s","OPCNT")' % (mondisks[0]["device"] if mondisks else "SYS$SYSDEVICE"))
m = re.search(r"OPS\|(\d+)", dka)
check([d["device"] for d in mondisks] == sysdisks and all(o > 0 for o in ops) and m and int(m.group(1)) >= ops[0],
      "each disk the dashboard lists, in its order, with its operation count (F$GETDVI OPCNT %s, after)" % (m.group(1) if m else "?"),
      ([d["device"] for d in mondisks], sysdisks, ops))

users = {p["username"] for p in b.get("visible", [])}
check(users == {"STEWARD_TEST"} or users == set(), "STEWARD_TEST: only its own processes (%d)" % len(b.get("visible", [])), users)
st, w = api("STEWARD_ADM", "WORLD", "/api/v1/monitor")
wusers = {p["username"] for p in (w or {}).get("visible", [])}
check(st == 200 and "SYSTEM" in wusers and len((w or {}).get("visible", [])) >= (w or {}).get("processes", 0) - 3,
      "STEWARD_ADM with WORLD: everyone's (%d of %d)" % (len((w or {}).get("visible", [])), (w or {}).get("processes", 0)),
      sorted(wusers)[:8])
st, n = api("STEWARD_ADM", "-", "/api/v1/monitor")
check(st == 200 and {p["username"] for p in (n or {}).get("visible", [])} <= {"STEWARD_ADM"},
      "STEWARD_ADM with WORLD authorized but not switched on: only its own (D9)")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
