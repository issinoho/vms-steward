"""phase9_live.py - Phase 9 (9a) on a VMS node: queues and jobs through the real
dispatcher and platform (tests/vms/api_probe), checked against SHOW QUEUE and
F$GETQUI.

    python3 tests/vms/phase9_live.py [node]      (default x86; run from the repo top)

Holds two jobs in SYS$BATCH (SUBMIT/HOLD: they never run), one as STEWARD_TEST and
one as the work account, and deletes them and their procedures at the end, whatever
happens. Otherwise read-only."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    fields = next(l.split() for l in f if l.split() and l.split()[0] == NODE)
WORKDIR, ME = fields[5], fields[4].upper()
AP = 'ap = "$' + WORKDIR[:-1] + '.BUILD]API_PROBE.EXE"'
TEST_COM = "SYS$SYSDEVICE:[STEWARD_TEST]P9L_HELD.COM"
MY_COM = WORKDIR[:-1] + ".BUILD]P9L_HELD.COM"

def vms(*cmds):
    return subprocess.run(["timeout", "120", "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
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

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

entries = []
try:
    out = vms("open/write f " + TEST_COM, 'write f "$ exit"', "close f", "set security/owner=STEWARD_TEST " + TEST_COM,
              "submit/hold/user=steward_test/noprint/nolog_file/name=P9L_TEST " + TEST_COM,
              "open/write f " + MY_COM, 'write f "$ exit"', "close f",
              "submit/hold/noprint/nolog_file/name=P9L_ME " + MY_COM)
    entries = re.findall(r"Job P9L_\w+ \(queue \S+, entry (\d+)\)", out)
    check(len(entries) == 2, "two held jobs: STEWARD_TEST's and the work account's", out[-300:])
    t_entry, m_entry = (entries + ["0", "0"])[:2]

    # "Batch queue X86VMS_BATCH, available, ..." but "Generic batch queue SYS$BATCH": a
    # generic queue's line has no comma.
    shown = set(re.findall(r"^\S.*? queue ([A-Z0-9$_]+)", vms("show queue *"), re.M))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/queues")
    ours = {q["name"] for q in (doc or {}).get("queues", [])}
    check(st == 200 and ours and ours == shown, "every queue, as SHOW QUEUE lists them (%d)" % len(ours), (ours, shown))

    st, doc = api("STEWARD_TEST", "-", "/api/v1/queues/SYS$BATCH")
    jobs = {str(j["entry"]): j for j in (doc or {}).get("jobs", [])}
    tj, mj = jobs.get(t_entry), jobs.get(m_entry)
    check(st == 200 and tj and tj["accessible"] and tj["name"] == "P9L_TEST" and tj["status"] == ["holding"],
          "STEWARD_TEST: its own held job in full", tj)
    check(mj and not mj["accessible"] and mj["name"] == "" and mj["username"] == "",
          "and the work account's as inaccessible, entry and status only", mj)
    st, doc = api("STEWARD_TEST", "-", "/api/v1/jobs/" + m_entry)
    check(st == 403 and "NOPRIV" in json.dumps(doc), "that job by entry: NOPRIV", (st, doc))

    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/jobs/" + m_entry)
    want = vms('write sys$output "F|", f$getqui("DISPLAY_ENTRY", "JOB_NAME", %s), "|", f$getqui("DISPLAY_ENTRY", "USERNAME", %s)' % (m_entry, m_entry))
    m = re.search(r"^F\|(.*)\|(.*)$", want, re.M)
    check(st == 200 and m and doc["name"] == m.group(1).strip() and doc["username"] == m.group(2).strip() and
          doc["files"] and doc["files"][0].upper().split(":", 1)[-1].startswith(MY_COM.upper().split(":", 1)[-1]),
          "STEWARD_ADM with SYSPRV: the work account's job, as F$GETQUI gives it, with its file", (st, doc, want[-200:]))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/jobs/99999999")
    check(st == 404 and "NOSUCH" in json.dumps(doc), "no such entry: 404, OpenVMS's NOSUCHENT", (st, doc))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/queues/NO_SUCH_QUEUE")
    check(st == 404 and "NOSUCHQUE" in json.dumps(doc), "no such queue: NOSUCHQUE", (st, doc))
finally:
    vms(*(["delete/entry=" + e for e in entries] + ["delete/nolog %s;*" % TEST_COM, "delete/nolog %s;*" % MY_COM]))
    left = vms('pipe show queue/batch/all * | search sys$pipe "P9L_"')
    check("P9L_" not in left.replace("search sys$pipe", ""), "the held jobs are gone", left[-200:])

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
