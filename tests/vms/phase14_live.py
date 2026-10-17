"""phase14_live.py - Phase 14 on a VMS node: the error log through the real dispatcher
and platform (tests/vms/api_probe), checked against ELV, the CLUE listings, OPERATOR.LOG
and the device error counts as the work account reads them.

    python3 tests/vms/phase14_live.py [node]      (default x86; run from the repo top)

READ-ONLY. With PHASE14_HELPER unset it stages vms/steward_errlog.com under
[STEWARD_TEST.P14T] (the helper runs as the viewer, who must read it) and removes it
after; with PHASE14_HELPER=installed it uses STEWARD$ROOT:[COM]STEWARD_ERRLOG.COM.
STEWARD_ADM holds SYSPRV authorized, not default (D9)."""
import json, os, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P14T]"
INSTALLED = os.environ.get("PHASE14_HELPER") == "installed"
HELPER = None if INSTALLED else STAGE + "STEWARD_ERRLOG.COM"
ROW = re.compile(r"^(\d+)\s+(.+?)\s{2,}(\d{1,2}-[A-Z]{3}-\d{4} \d\d:\d\d:\d\d\.\d\d)\s+(\S+)\s+(\S+)\s*$")

def vms(*cmds, timeout=300):
    return subprocess.run(["timeout", str(timeout), "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path):
    pre = ['define/nolog API_PROBE_ERRLOG_HELPER "%s"' % HELPER] if HELPER else []
    out = vms(*([AP] + pre + ['ap %s %s "%s"' % (user, privs, path)]))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):body.rindex("}") + 1]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def elv(quals):
    """ELV run by the work account, with SYSPRV, into a file read back."""
    lis = WORKDIR + "P14REF.LIS"
    return vms("set process/privilege=sysprv",
               "analyze/error_log/elv translate%s/output=%s" % (quals, lis),
               "type " + lis, "delete/nolog %s;*" % lis, timeout=600)

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
            "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR",
            "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_errlog.com " + STAGE)

    # ---- the events
    ref30 = [int(m.group(1)) for m in (ROW.match(l) for l in elv("/one_line/since=-30-").split("\n")) if m]
    check(len(ref30) > 0, "ELV, run by the work account, lists %d events in the last 30 days" % len(ref30))

    st, doc = api("STEWARD_TEST", "-", "/api/v1/errorlog")
    det = (doc or {}).get("detail", "")
    check(st == 403 and "FILOPNERR" in det and "-RMS-E-FNF" in det and "ELV reports a file it may not read as not found" in det,
          "STEWARD_TEST: refused with ELV's own words (file not found), and why", (st, det))
    st, doc = api("STEWARD_ADM", "-", "/api/v1/errorlog")
    check(st == 403, "STEWARD_ADM with SYSPRV authorized but not switched on: refused (D9)", st)
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog")
    got = [e["number"] for e in (doc or {}).get("events", [])]
    check(st == 200 and got[:len(ref30)] == ref30 and all(n > ref30[-1] for n in got[len(ref30):]),
          "STEWARD_ADM with SYSPRV: the same %d events, in ELV's order (and any written since)" % len(got), (st, got[:5], ref30[:5]))
    ev = (doc or {}).get("events", [{}])
    check(st == 200 and all(re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d", e.get("time", "")) and e.get("class") and e.get("type")
                            for e in ev), "each with an ISO time, a type and a class")

    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog?days=0")
    allev = (doc or {}).get("events", [])
    check(st == 200 and allev and allev[0]["number"] == 1 and len(allev) >= len(got) and not doc.get("truncated"),
          "days=0: the whole file, from event 1 (%d events)" % len(allev))
    crash = [e for e in allev if e["type"] == "Crash Restart"]
    if crash:
        n = crash[-1]["number"]
        st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog/%d" % n)
        fields = (doc or {}).get("fields", [])
        ref = elv("/entry=(start:%d,end:%d)" % (n, n))
        reffields = [l for l in ref.split("\n") if re.match(r"^ {3}\S", l)]
        arch = next((f for f in fields if f.get("description") == "Hardware Architecture"), {})
        check(st == 200 and doc["event"]["number"] == n and doc["event"]["type"] == "Crash Restart" and
              len(fields) >= len(reffields) - 2 and arch.get("value") == "5" and arch.get("translated") == "Intel X86",
              "event %d, the latest crash restart: %d fields as ELV gives them (%d top-level lines)" % (n, len(fields), len(reffields)),
              (st, len(fields), len(reffields), arch))
        mode = next((f for f in fields if f.get("description") == "Current Mode"), {})
        check(mode.get("indent") == 1 and mode.get("range") == "<04:03>:", "a bit field indented under its register", mode)
    else:
        check(False, "a crash restart to translate")
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog/99999999")
    check(st == 404, "an event not in the file: 404", st)

    # ---- the crashes
    names = sorted(re.findall(r"(CLUE\$[A-Z0-9_]+_\d{6}_\d{4}\.LIS);\d+", vms("directory/nohead/notrail SYS$ERRORLOG:CLUE$*.LIS")))
    st, doc = api("STEWARD_TEST", "-", "/api/v1/crashes")
    check(st == 403 and "privilege" in json.dumps(doc or {}).lower(), "STEWARD_TEST: the crash listings refused (PRV)", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes")
    got = sorted(c["name"] for c in (doc or {}).get("crashes", []))
    check(st == 200 and got == names, "with SYSPRV: the %d listings in SYS$ERRORLOG" % len(got), (got[:3], names[:3]))
    newest = max((doc or {}).get("crashes", [{"time": ""}]), key=lambda c: c["time"])
    if newest.get("name"):
        refsum = vms("set process/privilege=sysprv", "search SYS$ERRORLOG:%s \"Bugcheck Type:\",\"Crash Time:\"" % newest["name"])
        m = re.search(r"Bugcheck Type:\s+(.+?)\s*$", refsum, re.M)
        check(m and newest["bugcheck"] == m.group(1), "the newest, %s: bugcheck %s, as in the listing" % (newest["time"], newest["bugcheck"]),
              (newest, refsum[:200]))
        st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes/" + newest["name"])
        text = (doc or {}).get("text", "")
        check(st == 200 and "Crashdump Summary Information" in text and any(s["key"] == "Crash Time" for s in doc.get("summary", [])),
              "its summary and whole listing (%d lines)" % text.count("\n"))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes/SYSUAF.DAT")
    check(st == 400, "nothing but a CLUE listing by name", st)

    # ---- OPCOM's log
    st, doc = api("STEWARD_TEST", "-", "/api/v1/operator-log")
    check(st == 403, "STEWARD_TEST: OPCOM's log refused", st)
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/operator-log?stamps=1")
    tail = vms("set process/privilege=sysprv", "directory/nohead/notrail SYS$MANAGER:OPERATOR.LOG;0",
               "type/tail=40 SYS$MANAGER:OPERATOR.LOG")
    ver = re.search(r"OPERATOR\.LOG;(\d+)", tail)
    heads = re.findall(r"%{11}  OPCOM  (\d{1,2}-[A-Z]{3}-\d{4} \d\d:\d\d:\d\d)\.\d\d  %{11}", tail)
    msgs = (doc or {}).get("messages", [])
    check(st == 200 and ver and doc.get("file", "").endswith("OPERATOR.LOG;" + ver.group(1)),
          "with SYSPRV: the newest version, %s" % (doc or {}).get("file"), ((doc or {}).get("file"), ver and ver.group(1)))
    if heads and msgs:
        d, mon, y = heads[-1].split()[0].split("-")
        months = "JANFEBMARAPRMAYJUNJULAUGSEPOCTNOVDEC"
        want = "%s-%02d-%02dT%s" % (y, months.index(mon) // 3 + 1, int(d), heads[-1].split()[1])
        check(msgs[0]["time"] >= want, "newest first: %s, the file's last message %s" % (msgs[0]["time"], want))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/operator-log")
    check(st == 200 and not any(m.get("stamp") for m in doc.get("messages", [])), "without stamps=1, no hourly stamps")

    # ---- device errors
    ref = vms('ctx = ""', 'l: d = f$device("*", , , ctx)', 'if d .eqs. "" then goto e',
              'n = f$getdvi(d, "ERRCNT")', 'if n .gt. 0 then write sys$output "ERR ", d, " ", n', 'goto l', 'e: write sys$output "DONE"')
    referr = re.findall(r"^ERR (\S+) (\d+)", ref, re.M)
    st, doc = api("STEWARD_TEST", "-", "/api/v1/device-errors")
    check(st == 200 and doc["scanned"] > 0 and len(doc["devices"]) == len(referr),
          "device errors for anyone: %d with errors of %d, as F$GETDVI ERRCNT says (%d)" % (len(doc["devices"]), doc["scanned"], len(referr)),
          (doc, referr))
finally:
    if HELPER:
        vms("delete/nolog %s*.*;*" % STAGE,
            "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR",
            "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR;*")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
