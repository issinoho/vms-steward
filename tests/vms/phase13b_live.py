"""phase13b_live.py - Phase 13b on a VMS node: the monitoring recorder (D22).

    python3 tests/vms/phase13b_live.py [node]      (default x86; run from the repo top)

Runs tests/vms/phase13b_rec.com in batch: the recorder (steward -r) for 40 s at 5 s into
a scratch recording in [.BUILD], read back through the real dispatcher and platform
(api_probe) as STEWARD_TEST, beside a live reading. Then tests/vms/phase13b_pool.com:
STEWARD_POOL.COM starting, listing and stopping the recorder in a test pool of the work
directory's own ([.P13BRUN], base 19390), never the installed one. Everything here is
the work account's: its own subprocess and detached process, stopped by PID or by the
pool procedure's STOP."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"

def batch(com):
    return subprocess.run(["tools/vms.sh", NODE, "batch", com], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          encoding="latin-1", timeout=900).stdout.replace("\r", "")

def section(out, name):
    m = re.search(r"==%s==(.*?)(?===[A-Z]+==|\Z)" % name, out, re.S)
    return m.group(1) if m else ""

def doc(text):
    m = re.search(r"^(\d{3})\s*$", text, re.M)
    body = text[m.end():].replace("\n", "") if m else ""
    try:
        return (int(m.group(1)) if m else None), (json.loads(body[body.index("{"):body.rindex("}") + 1]) if "{" in body else None)
    except ValueError:
        return (int(m.group(1)) if m else None), None

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

out = batch("tests/vms/phase13b_rec.com")
reclog = section(out, "RECLOG")
check("recording is off" in out, "STEWARD_RECORD_SECS 0: the recorder says it is off and stops")
check("must be 5 to 3600" in out, "an interval below 5 s refused")
pid = section(out, "PID").strip()
check(re.fullmatch(r"[0-9A-F]{8}", pid or "") and "recording every 5 s, 17280 slots" in reclog,
      "the recorder started: every 5 s, a day of 17,280 slots (pid %s)" % pid, reclog[:300])
parent = section(out, "PARENTPRIV").strip()
cur, perm = section(out, "CURPRIV").strip(), section(out, "PROCPRIV").strip()
check(set(cur.split(",")) == {"TMPMBX", "NETMBX"} and set(perm.split(",")) == {"TMPMBX", "NETMBX"},
      "its privileges, current and permanent: TMPMBX and NETMBX only (started with %s)" % parent, (cur, perm))

st, h = doc(section(out, "HIST"))
h = h or {}
rd = h.get("readings", [])
check(st == 200 and h.get("recording") is True and h.get("interval_secs") == 5 and h.get("kept_secs") == 86400 and
      h.get("step_secs") == 5, "STEWARD_TEST reads the recording: 5 s, a day, every reading", (st, {k: v for k, v in h.items() if k != "readings"}))
times = [r["sampled_at_ms"] for r in rd]
gaps = [b - a for a, b in zip(times, times[1:])]
check(7 <= len(rd) <= 10 and all(g == 5000 or abs(g - 5000) < 1500 for g in gaps),
      "%d readings over 40 s, 5 s apart (%s)" % (len(rd), sorted(set(round(g / 1000.0, 1) for g in gaps))), gaps)
check(all(abs(t - round(t / 5000.0) * 5000) < 1500 for t in times),
      "each taken on an interval's boundary (within %d ms)" % max([abs(t - round(t / 5000.0) * 5000) for t in times] or [0]))
st2, live = doc(section(out, "LIVE"))
live = live or {}
if rd and live:
    last = rd[-1]
    dt = (live["sampled_at_ms"] - last["sampled_at_ms"]) / 1000.0
    back = [k for k in last["counters"] if live["counters"][k] < last["counters"][k]]
    back += [k for k in last["modes"] if k != "interrupt" and live["modes"][k] < last["modes"][k]]
    check(0 <= dt < 15 and not back and live["cpus"] == last["cpus"] and
          [d["device"] for d in live["disks"]] == [d["device"] for d in last["disks"]] and
          abs(live["processes"] - last["processes"]) <= 5,
          "the last recorded reading agrees with a live one %.1f s later (counters on, same CPUs and disks)" % dt, back)
    ticks = sum(rd[-1]["modes"][k] - rd[0]["modes"][k] for k in rd[0]["modes"])
    cap = 100 * last["cpus"] * (rd[-1]["sampled_at_ms"] - rd[0]["sampled_at_ms"]) / 1000.0
    check(cap > 0 and abs(ticks / cap - 1) < 0.1, "between the first and last, the mode ticks add up to the CPUs' (%d of %d)" % (ticks, cap))
    check("visible" not in last and "visible" in live, "no processes in the recording; the live reading has them")
else:
    check(False, "a recorded and a live reading to compare", (st2, len(rd)))
st, thin = doc(section(out, "THIN"))
thin = thin or {}
check(st == 200 and thin.get("step_secs") == 30 and 1 <= len(thin.get("readings", [])) <= 2,
      "1 minute in 2 points: 30 s apart, from the same ring", (thin.get("step_secs"), len(thin.get("readings", []))))
st, nf = doc(section(out, "NOFILE"))
check(st == 200 and nf == {"recording": False, "readings": []}, "without a recording file: recording false, nothing else", nf)
d = section(out, "DIR")
m = re.search(r"P13B_MONITOR\.DAT;1\s+(\d+)/(\d+)", d)
check(m and int(m.group(1)) < 200, "the file small for a few readings (%s blocks used)" % (m.group(1) if m else "?"), d[:300])

out = batch("tests/vms/phase13b_pool.com")
start, status, after = section(out, "START"), section(out, "STATUS"), section(out, "AFTER")
check("started STEWARD_R19390 (monitoring recorder)" in start, "the pool starts the recorder, STEWARD_R19390", start[-300:])
m = re.search(r"STEWARD_R19390 pid ([0-9A-F]{8}) user (\S+).*?\n\s+privileges: (\S+)", status, re.S)
check(m and set(m.group(3).split(",")) == {"TMPMBX", "NETMBX"},
      "STATUS lists it, with TMPMBX and NETMBX only (%s)" % (m.group(3) if m else "?"), status[-400:])
st, ph = doc(section(out, "HIST"))
ph = ph or {}
check(st == 200 and ph.get("recording") and ph.get("interval_secs") == 5 and len(ph.get("readings", [])) >= 2,
      "it records into the pool's MONITOR.DAT (%d readings)" % len(ph.get("readings", [])))
check("stopped STEWARD_R19390" in section(out, "STOP") and "STEWARD_R19390 not running" in after,
      "STOP stops it", section(out, "STOP")[-300:])
prot = section(out, "PROT").strip()
check(prot.replace(" ", "") in ("SYSTEM=RWED,OWNER=RWED,GROUP=,WORLD=", "SYSTEM=RWED,OWNER=RWED,GROUP,WORLD"),
      "MONITOR.DAT private to the account (%s)" % prot)
check("the recorder is off (STEWARD_RECORD_SECS 0)" in section(out, "OFFSTART") and "started STEWARD_R" not in section(out, "OFFSTART"),
      "STEWARD_RECORD_SECS 0: the pool does not start it", section(out, "OFFSTART")[-300:])

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
