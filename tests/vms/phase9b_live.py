"""phase9b_live.py - Phase 9b on a VMS node: holding, releasing and deleting jobs and
stopping and starting a queue through the real dispatcher and platform
(tests/vms/api_probe), checked with F$GETQUI and SHOW QUEUE.

    python3 tests/vms/phase9b_live.py [node]      (default x86; run from the repo top)

CHANGES JOBS AND A QUEUE, but only its own: three held jobs it submits (two as
STEWARD_TEST, one as the work account, each only "$ EXIT") and a test queue it creates
stopped (STEWARD_P9B_TEST, as the user agreed, 2026-10-15). It deletes them all at the
end, whatever happens. Steward's start-up queues (SYS$BATCH and what it feeds) are
asked to stop only as STEWARD_TEST, who may not stop any queue: a guard that failed
would still meet the queue manager's NOPRIV, never stop a real queue."""
import json, re, subprocess, sys, time

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
AUDIT = BUILD + "PROBE_9B_AUDIT.LOG"
TEST_COM = "SYS$SYSDEVICE:[STEWARD_TEST]P9BL_HELD.COM"
MY_COM = BUILD + "P9BL_HELD.COM"
QUEUE = "STEWARD_P9B_TEST"

def vms(*cmds):
    return subprocess.run(["timeout", "120", "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path, method="GET"):
    out = vms(AP, "define/nolog API_PROBE_AUDIT " + AUDIT, 'ap %s %s "%s" "%s"' % (user, privs, path, method))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def job_status(entry):
    out = vms('write sys$output "S|", f$getqui("DISPLAY_ENTRY", "JOB_STATUS", %s)' % entry)
    m = re.search(r"^S\|(-?\d*)", out, re.M)
    return int(m.group(1)) if m and m.group(1) else None   # None: no such entry

def queue_line():
    return next((l for l in vms("show queue " + QUEUE).splitlines() if QUEUE in l), "")

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

# The node's own names, not x86's: the test queue goes on this node, and Steward's
# start-up queues are SYS$BATCH and, when it is generic, what it feeds (X86VMS_BATCH on
# x86; on IA64 SYS$BATCH is itself an execution queue).
names = vms('write sys$output "N|", f$getsyi("SCSNODE")',
            'write sys$output "T|", f$getqui("DISPLAY_QUEUE", "GENERIC_TARGET", "SYS$BATCH")')
SCSNODE = (re.search(r"^N\|(\S+)", names, re.M) or [None, "X86VMS"])[1]
STARTUP = ["SYS$BATCH"] + [q for q in re.split(r"[\s,]+", (re.search(r"^T\|(.*)$", names, re.M) or [None, ""])[1]) if q]

entries = []
try:
    out = vms("delete/nolog " + AUDIT + ";*", "open/write f " + TEST_COM, 'write f "$ exit"', "close f",
              "set security/owner=STEWARD_TEST " + TEST_COM,
              "submit/hold/user=steward_test/noprint/nolog_file/name=P9BL_A " + TEST_COM,
              "submit/hold/user=steward_test/noprint/nolog_file/name=P9BL_B " + TEST_COM,
              "open/write f " + MY_COM, 'write f "$ exit"', "close f",
              "submit/hold/noprint/nolog_file/name=P9BL_C " + MY_COM,
              "initialize/queue/batch/on=%s::/job_limit=1 %s" % (SCSNODE, QUEUE))
    entries = re.findall(r"Job P9BL_\w+ \(queue \S+, entry (\d+)\)", out)
    check(len(entries) == 3 and "stopped" in queue_line(), "three held jobs and a stopped test queue", out[-300:])
    a, b, c = (entries + ["0"] * 3)[:3]

    st, doc = api("STEWARD_TEST", "-", "/api/v1/jobs/%s/release" % a, "POST")
    time.sleep(2)
    s = job_status(a)
    check(st == 200 and (s is None or not (s & 0x4)), "STEWARD_TEST releases its own held job (it ran)", (st, doc, s))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/jobs/" + c, "DELETE")
    check(st == 403 and "NOPRIV" in json.dumps(doc) and job_status(c) is not None,
          "STEWARD_TEST may not delete the work account's: JBC NOPRIV, still there", (st, doc))
    st, doc = api("STEWARD_ADM", "-", "/api/v1/jobs/%s/hold" % b, "POST")
    check(st == 403, "STEWARD_ADM may not change its group's job (read only, G:R)", (st, doc))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/jobs/" + b, "DELETE")
    check(st == 200 and job_status(b) is None, "STEWARD_TEST deletes its own: gone, as DELETE/ENTRY", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/jobs/" + c, "DELETE")
    check(st == 200 and job_status(c) is None, "with SYSPRV, the work account's job deleted", (st, doc))

    st, doc = api("STEWARD_ADM", "-", "/api/v1/queues/%s/start" % QUEUE, "POST")
    check(st == 403 and "stopped" in queue_line(), "starting the test queue without SYSPRV: NOPRIV, still stopped", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/queues/%s/start" % QUEUE, "POST")
    check(st == 200 and "stopped" not in queue_line() and "stopped" not in doc["status"],
          "with SYSPRV: started, as START/QUEUE", (st, doc, queue_line()))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/queues/%s/stop" % QUEUE, "POST")
    check(st == 200 and "stopped" in queue_line(), "and stopped, as STOP/QUEUE", (st, doc, queue_line()))

    for q in STARTUP:
        st, doc = api("STEWARD_TEST", "-", "/api/v1/queues/%s/stop" % q, "POST")
        check(st == 409 and "startup-queue" in json.dumps(doc),
              "%s: refused as Steward's start-up queue (409), before the queue manager is asked" % q, (st, doc))

    log = vms("type " + AUDIT)
    check('action="job-delete"' in log and 'action="queue-start" target="%s" outcome="ok"' % QUEUE in log and
          'action="queue-stop" target="SYS$BATCH" outcome="refused"' in log and 'outcome="failed" detail="%JBC-E-NOPRIV' in log,
          "audited on the node: changes, refusals and NOPRIV", log[-500:])
finally:
    vms(*(["delete/entry=" + e for e in entries] +
          ["stop/queue/next " + QUEUE, "delete/queue " + QUEUE,
           "delete/nolog %s;*" % TEST_COM, "delete/nolog %s;*" % MY_COM, "delete/nolog %s;*" % AUDIT]))
    left = vms('pipe show queue/batch/all * | search sys$pipe "P9BL_","%s"' % QUEUE)
    check("P9BL_" not in left.replace("search sys$pipe", "").replace('"P9BL_"', "") and
          QUEUE + "," not in left, "the test jobs and queue are gone", left[-300:])
    st = vms(*["show queue " + q for q in STARTUP])
    check("stopped" not in st.lower(), "%s not stopped" % " and ".join(STARTUP), st[-300:])

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
