"""phase14b_live.py - Phase 14b on a VMS node: the error log's changes (D24) and the
pool purging its logs (D25), through the real dispatcher and platform (api_probe).

    python3 tests/vms/phase14b_live.py [node]      (default x86; run from the repo top)

Nothing of the system's is changed: the work account copies ERRLOG.SYS into [.P14BELA]
and the three newest CLUE listings into [.P14BELB] of the work directory, and api_probe
is pointed (API_PROBE_ERRLOG_DIR) at P14BSL, a process search list of the two, as
SYS$ERRORLOG is a search list with ERRLOG.SYS in its first directory and the listings
in its second ($ERASE and $RENAME act on the first only: NOTES.md). The system's
SYS$ERRORLOG is checked unchanged at the end. The edited helper procedure is staged
under [STEWARD_TEST.P14T] as for phase14_live.py. The pool purge runs in a test pool of
the work directory's own ([.P14BRUN], base 19391) that starts no process."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
ELA = WORKDIR[:-1] + ".P14BELA]"
ELB = WORKDIR[:-1] + ".P14BELB]"
AUDIT = ELA + "AUDIT.LOG"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P14T]"
HELPER = STAGE + "STEWARD_ERRLOG.COM"

def vms(*cmds, timeout=300):
    return subprocess.run(["timeout", str(timeout), "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def dcl_quote(s):
    return '"' + s.replace('"', '""') + '"'

def api(user, privs, path, method="GET", body=None):
    run = 'ap %s %s "%s" "%s"' % (user, privs, path, method)
    if body is not None:
        run += " " + dcl_quote(json.dumps(body, separators=(",", ":")))
    out = vms(AP, 'define/nolog API_PROBE_ERRLOG_HELPER "%s"' % HELPER, 'define/nolog P14BSL %s,%s' % (ELA, ELB),
              'define/nolog API_PROBE_ERRLOG_DIR "P14BSL:"',
              'define/nolog API_PROBE_AUDIT "%s"' % AUDIT, run)
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    rest = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(rest[rest.index("{"):rest.rindex("}") + 1]) if "{" in rest else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def files(spec):
    return sorted(re.findall(r"([A-Z0-9_$]+\.(?:SYS|LIS));\d+", vms("set process/privilege=sysprv", "directory/nohead/notrail " + spec)))

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

real_before = files("SYS$ERRORLOG:ERRLOG.SYS,CLUE$*.LIS")
clue = [n for n in real_before if n.startswith("CLUE$")]
newest3 = sorted(clue, key=lambda n: n[-15:-9][4:6] + n[-15:-9][2:4] + n[-15:-9][0:2] + n[-8:-4])[-3:]
try:
    vms("create/directory/protection=(S:RWED,O:RWED,G,W) " + ELA,
        "create/directory/protection=(S:RWED,O:RWED,G,W) " + ELB,
        "create/directory/protection=(S:RWED,O:RWED,G:RE,W:RE) " + STAGE,
        "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR",
        "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_errlog.com " + STAGE,
        "set process/privilege=sysprv",
        "copy/protection=(S:RWED,O:RWED,G,W) SYS$ERRORLOG:ERRLOG.SYS " + ELA,
        *["copy/protection=(S:RWED,O:RWED,G,W) SYS$ERRORLOG:%s %s" % (n, ELB) for n in newest3])
    if not newest3:
        # A node with no crash listings (IA64, 2026-10-18): three of the test's own, in
        # CLUE's summary layout, dated in 2026's first months, in the scratch directory.
        node = re.search(r"NODE (\S+)", vms('write sys$output "NODE ", f$getsyi("NODENAME")')).group(1)
        for d, m, hm in (("15", "01", "0910"), ("16", "02", "1020"), ("17", "03", "1130")):
            name = "CLUE$%s_%s%s26_%s.LIS" % (node, d, m, hm)
            mon = ("JAN", "FEB", "MAR")[int(m) - 1]
            vms("open/write w %s%s" % (ELB, name),
                'write w "Crashdump Summary Information:"',
                'write w "Crash Time:        %s-%s-2026 %s:%s:00.00"' % (d, mon, hm[:2], hm[2:]),
                'write w "Bugcheck Type:     TESTCRASH, made by phase14b_live.py"',
                'write w "Stack Pointers:"', "close w",
                "set security/protection=(S:RWED,O:RWED,G,W) %s%s" % (ELB, name))
            newest3.append(name)
    check(files(ELA + "*.*") == ["ERRLOG.SYS"] and files(ELB + "*.*") == sorted(newest3),
          "copies: ERRLOG.SYS in the search list's first directory, the three newest listings (%s) in its second" % ", ".join(newest3))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes")
    check(st == 200 and sorted(c["name"] for c in doc["crashes"]) == sorted(newest3), "the listings found through the search list")

    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog/files")
    check(st == 200 and [f["name"] for f in doc["files"]] == ["ERRLOG.SYS"] and doc["files"][0]["blocks"] > 0,
          "the files: ERRLOG.SYS alone, %s blocks" % (doc or {}).get("files", [{}])[0].get("blocks"), (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog?days=0")
    count = len((doc or {}).get("events", []))
    check(st == 200 and count > 0, "the copy read through the helper: %d events" % count)

    st, doc = api("STEWARD_TEST", "-", "/api/v1/errorlog/new", "POST", {})
    check(st == 403, "STEWARD_TEST: a new error log refused", (st, doc))
    st, doc = api("STEWARD_ADM", "-", "/api/v1/errorlog/new", "POST", {})
    check(st == 403, "STEWARD_ADM with SYSPRV not switched on: refused (D9)", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog/new", "POST", {})
    renamed = (doc or {}).get("renamed_to", "")
    check(st == 200 and re.fullmatch(r"ERRLOG_\d{8}_\d{4}\.SYS", renamed) and files(ELA + "*.SYS") == [renamed] and
          not files(ELB + "*.SYS"), "with SYSPRV: ERRLOG.SYS renamed %s, in its own directory" % renamed, (st, doc, files(ELA + "*.SYS")))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog")
    check(st == 404 and "ERRFMT creates it at its next record" in (doc or {}).get("detail", ""),
          "no ERRLOG.SYS until the next record, and the viewer told so", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog?days=0&file=" + renamed)
    check(st == 200 and len(doc["events"]) == count and doc["file"] == renamed,
          "the renamed log read by name: the same %d events" % count)
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/errorlog/new", "POST", {})
    check(st == 404, "no new log of a log not there", st)

    st, doc = api("STEWARD_TEST", "-", "/api/v1/crashes/" + newest3[0], "DELETE")
    check(st == 403, "STEWARD_TEST: deleting a listing refused (PRV)", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes/" + newest3[0], "DELETE")
    check(st == 204 and newest3[0] not in files(ELB + "*.LIS"), "with SYSPRV: %s deleted, from the second directory" % newest3[0], (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/crashes/purge", "POST", {"before": "2099-01-01"})
    check(st == 200 and sorted(doc["deleted"]) == sorted(newest3[1:]) and doc["failed"] == 0 and files(ELB + "*.LIS") == [],
          "purge before 2099: the other two", (st, doc))
    audit = vms("type " + AUDIT)
    check(re.search(r'action="errorlog-new" target="ERRLOG\.SYS" outcome="ok" detail="' + renamed, audit) and
          len(re.findall(r'action="crash-delete" target="[^"]+" outcome="ok"', audit)) == 3 and
          re.search(r'action="errorlog-new" target="ERRLOG\.SYS" outcome="failed"', audit) and
          re.search(r'user="STEWARD_TEST".*action="crash-delete".*outcome="failed"', audit),
          "each change, and each refusal, in the audit log", audit[-600:])

    # ---- the pool purges its logs (D25)
    out = vms("tdir = \"%s\"" % (WORKDIR[:-1] + ".P14BRUN]"),
              "tlogs = \"%s\"" % (WORKDIR[:-1] + ".P14BRUN.LOGS]"),
              "create/directory 'tdir'", "create/directory 'tlogs'",
              "open/write s 'tdir'STEWARD_SETTINGS.COM",
              'write s "$ define/process/nolog STEWARD_RECORD_SECS ""0"""',
              'write s "$ define/process/nolog STEWARD_LOG_KEEP ""5"""', "close s",
              "i = 0", "mk: open/write s 'tlogs'STEWARD_R19391.LOG", "close s",
              "open/write s 'tlogs'STEWARD_R19391.COM", "close s", "i = i + 1", "if i .lt. 15 then goto mk",
              "write sys$output \"BEFORE \", f$file_attributes(f$search(\"'tlogs'STEWARD_R19391.LOG\"), \"FID\")",
              "directory/nohead/notrail 'tlogs'", "write sys$output \"==START==\"",
              "@[.vms]steward_pool START 0 19391 \"''tdir'\" \"[.build]steward.exe\"",
              "write sys$output \"==AFTER==\"", "directory/nohead/notrail 'tlogs'")
    before, after = (out.split("==START==") + [""])[:2]
    after = after.split("==AFTER==")[-1]
    nb = len(re.findall(r"STEWARD_R19391\.LOG;\d+", before))
    na_log = len(re.findall(r"STEWARD_R19391\.LOG;\d+", after))
    na_com = len(re.findall(r"STEWARD_R19391\.COM;\d+", after))
    check(nb == 15 and na_log == 5 and na_com == 5 and "the recorder is off" in out,
          "the pool's START purges [.LOGS] to STEWARD_LOG_KEEP: %d versions of each became %d and %d" % (nb, na_log, na_com),
          out[-500:])
finally:
    vms("set process/privilege=sysprv",
        "delete/nolog %s*.*;*" % ELA, "set security/protection=(O:RWED) %sP14BELA.DIR;1" % WORKDIR,
        "delete/nolog %sP14BELA.DIR;1" % WORKDIR,
        "delete/nolog %s*.*;*" % ELB, "set security/protection=(O:RWED) %sP14BELB.DIR;1" % WORKDIR,
        "delete/nolog %sP14BELB.DIR;1" % WORKDIR,
        "delete/nolog %s*.*;*" % STAGE, "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR",
        "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P14T.DIR;*",
        "delete/nolog %s*.*;*" % (WORKDIR[:-1] + ".P14BRUN.LOGS]"),
        "set security/protection=(O:RWED) %sLOGS.DIR;1" % (WORKDIR[:-1] + ".P14BRUN]"),
        "delete/nolog %sLOGS.DIR;1" % (WORKDIR[:-1] + ".P14BRUN]"),
        "delete/nolog %s*.*;*" % (WORKDIR[:-1] + ".P14BRUN]"),
        "set security/protection=(O:RWED) %sP14BRUN.DIR;1" % WORKDIR,
        "delete/nolog %sP14BRUN.DIR;1" % WORKDIR)

check(files("SYS$ERRORLOG:ERRLOG.SYS,CLUE$*.LIS") == real_before,
      "the system's SYS$ERRORLOG unchanged: ERRLOG.SYS and its %d listings" % len(clue))
print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
