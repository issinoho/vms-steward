"""phase8b_live.py - Phase 8b on a VMS node: stopping processes through the real
dispatcher and platform (tests/vms/api_probe), checked with F$GETJPI.

    python3 tests/vms/phase8b_live.py [node]      (default x86; run from the repo top)

STOPS PROCESSES, but only batch jobs it submits itself as STEWARD_TEST, each waiting
a few minutes; at the end it deletes any still there, and the procedure. It never
names a pool process: api_probe runs in the work account, which it would take for
the service account, so a stop of the pool would not be refused (that stopped the
real STEWARD_19300 on 2026-10-15). The refusal is checked on one of its own jobs
instead, with API_PROBE_SERVICE_ACCOUNT=STEWARD_TEST. STEWARD_ADM needs GROUP
authorized (the user agreed, 2026-10-15)."""
import json, re, subprocess, sys, time

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
AUDIT = BUILD + "PROBE_8B_AUDIT.LOG"
WAIT = "SYS$SYSDEVICE:[STEWARD_TEST]P8B_WAIT.COM"

def vms(*cmds):
    return subprocess.run(["tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path, method="GET", own=None, image=None, sysgroup=None):
    pre = ["define/nolog API_PROBE_SERVICE_ACCOUNT " + own] if own else []
    pre += ["define/nolog API_PROBE_MAX_SYS_GROUP " + sysgroup] if sysgroup else []
    pre += ["define/nolog API_PROBE_SERVICE_IMAGE " + image] if image else []
    out = vms(*([AP, "define/nolog API_PROBE_AUDIT " + AUDIT] + pre +
                ['ap %s %s "%s" "%s"' % (user, privs, path, method)]))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def exists(pid):
    out = vms('write sys$output "E|", f$getjpi("%s", "PRCNAM")' % pid)
    return "E|" in out and "NONEXPR" not in out and bool(re.search(r"^E\|\S", out, re.M))

def jobs():
    """The PIDs of this test's batch jobs: STEWARD_TEST's BATCH_ processes (it runs
    nothing else), from tests/vms/phase8_jpi.com."""
    out = subprocess.run(["tools/vms.sh", NODE, "run", "tests/vms/phase8_jpi.com"], stdout=subprocess.PIPE,
                         encoding="latin-1").stdout
    return sorted(m.group(1) for m in re.finditer(r"^P\|(\w+)\|BATCH_\d+\|STEWARD_TEST\|", out, re.M))

QUEUES = 'pipe show queue/batch/all * | search sys$pipe "P8B_"'

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

try:
    vms("delete/nolog " + AUDIT + ";*", "open/write f " + WAIT, 'write f "$ wait 00:05:00"', "close f",
        "set security/owner=STEWARD_TEST " + WAIT,
        *["submit/user=steward_test/noprint/nolog_file/name=P8B_%d %s" % (i, WAIT) for i in (1, 2, 3, 4)])
    time.sleep(3)
    pids = jobs()
    # The queue runs three at once here: the fourth starts once two are stopped.
    check(len(pids) >= 3, "batch jobs as STEWARD_TEST to stop", pids)
    a, b, c = (pids + ["00000000"] * 3)[:3]

    st, doc = api("STEWARD_ADM", "-", "/api/v1/processes/" + a, "DELETE")
    check(st == 403 and "NOPRIV" in json.dumps(doc) and exists(a),
          "STEWARD_ADM without GROUP: NOPRIV, the job untouched", (st, doc))
    st, doc = api("STEWARD_ADM", "GROUP", "/api/v1/processes/" + a, "DELETE")
    time.sleep(2)
    check(st == 202 and doc["name"].startswith("BATCH_") and not exists(a),
          "with GROUP: 202, and the job gone, as STOP/ID", (st, doc))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/processes/" + b, "DELETE")
    time.sleep(2)
    check(st == 202 and not exists(b), "STEWARD_TEST stops its own job", (st, doc))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/processes/" + b, "DELETE")
    check(st == 404 and "NONEXPR" in json.dumps(doc), "and again: NONEXPR", (st, doc))

    # "Steward's own" made STEWARD_TEST's for this request: refused, the job untouched.
    st, doc = api("STEWARD_ADM", "GROUP", "/api/v1/processes/" + c, "DELETE", own="STEWARD_TEST")
    check(st == 409 and exists(c), "a process of the service account: refused (409), still running", (st, doc))

    # System processes (UIC group up to MAXSYSGROUP) are refused whatever the viewer
    # holds (OPCOM was stopped in the browser check). Never tried on a real one: group
    # 362 is named the system groups' top for this request, so a job of ours counts.
    time.sleep(3)
    sysjob = next((p for p in jobs() if p not in (a, b, c)), "00000000")
    st, doc = api("STEWARD_ADM", "WORLD", "/api/v1/processes/" + sysjob, "DELETE", sysgroup="362")
    check(st == 409 and "system-process" in json.dumps(doc) and exists(sysjob),
          "a system process: refused (409) with WORLD, still running", (st, doc))
    opcom = re.search(r"^O\|(\w+)", vms('ctx = ""', 'loop: pid = f$pid(ctx)', 'if pid .eqs. "" then goto done',
        'if f$getjpi(pid, "PRCNAM") .eqs. "OPCOM" then write sys$output "O|", pid', 'goto loop', 'done:'), re.M)
    if opcom:
        st, doc = api("STEWARD_ADM", "WORLD", "/api/v1/processes/" + opcom.group(1))
        check(st == 200 and doc["system"] is True, "OPCOM's page says system, from the node's MAXSYSGROUP (read only)", (st, doc and doc.get("system")))

    # A pool worker busy with a request holds the requester's persona and is reported
    # under their name (NOTES.md). probe_hold stands in for one: a process of the work
    # account holding STEWARD_TEST's persona, its image named as Steward's.
    T = WORKDIR[:-1]
    vms("open/write f %s.PROBES]HOLD.COM" % T,
        'write f "$ ph = ""$%s.PROBES]PROBE_HOLD.EXE"""' % T, 'write f "$ ph steward_test 60"', "close f",
        "run/detach/process_name=P8B_HOLD/output=%s.PROBES]HOLD.LOG sys$system:loginout/input=%s.PROBES]HOLD.COM" % (T, T))
    time.sleep(4)
    hold = re.search(r"^H\|(\w+)\|(.*)$", vms('ctx = ""', 'loop: pid = f$pid(ctx)', 'if pid .eqs. "" then goto done',
        'if f$getjpi(pid, "PRCNAM") .eqs. "P8B_HOLD" then write sys$output "H|", pid, "|", f$getjpi(pid, "USERNAME")',
        'goto loop', 'done:'), re.M)
    check(hold and hold.group(2).strip().upper() == "STEWARD_TEST",
          "a process holding STEWARD_TEST's persona is reported under that name", hold and hold.groups())
    if hold:
        st, doc = api("STEWARD_ADM", "WORLD", "/api/v1/processes/" + hold.group(1), "DELETE", image="PROBE_HOLD.EXE")
        check(st == 409 and exists(hold.group(1)),
              "with WORLD, stopping it is refused by its image (409), still running", (st, doc))

    log = vms("type " + AUDIT)
    check('action="process-stop" target="%s \\"BATCH_' % a in log and 'outcome="ok"' in log and
          'outcome="refused" detail="Steward\'s own process"' in log and 'outcome="failed" detail="%SYSTEM-F-NOPRIV' in log,
          "audited on the node: stops, the refusal and NOPRIV", log[-500:])
finally:
    left = re.findall(r"^\s*(\d+)\s+P8B_", vms(QUEUES), re.M)
    vms(*(["delete/entry=" + e for e in left] + ["delete/nolog " + WAIT + ";*", "delete/nolog " + AUDIT + ";*"]))
    # probe_hold ends on its own after 60 s; its files go then (HOLD.LOG is open till).
    check(not re.findall(r"^\s*\d+\s+P8B_", vms(QUEUES), re.M),
          "no test job left", left)

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
