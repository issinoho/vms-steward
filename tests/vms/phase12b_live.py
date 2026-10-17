"""phase12b_live.py - Phase 12b on a VMS node: installing and removing a product through
the real dispatcher and platform (tests/vms/api_probe), as STEWARD_ADM.

    python3 tests/vms/phase12b_live.py [node] [privileges]   (default x86 SYSPRV,SYSLCK)

CHANGES THE SYSTEM, as the user allowed on 2026-10-17 (PHASE12.md): it installs the
demo kit ISSINOHO <base> STWDEMO V1.0 (probes/make_stwdemo.com, one text file) into a
destination under [STEWARD_TEST.P12T], which adds it to the PCSI database, and removes
it again. The edited procedures and a copy of the kit are staged in [STEWARD_TEST.P12T]
(world-readable, as the helper and the job run as STEWARD_ADM) and removed after; the
job's logs in STEWARD_ADM's login directory are removed too. Nothing else is touched:
Steward's own product and the operating system are only asked for, to see them
refused."""
import json, re, subprocess, sys, time

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
PRIVS = sys.argv[2] if len(sys.argv) > 2 else "SYSPRV,SYSLCK"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P12T]"
DEST = "SYS$SYSDEVICE:[STEWARD_TEST.P12T.DEST]"
BASE = "X86VMS" if NODE.startswith("x86") else "I64VMS"
DEMO = {"producer": "ISSINOHO", "base": BASE, "name": "STWDEMO"}

def vms(*cmds, timeout=300):
    return subprocess.run(["timeout", str(timeout), "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def dcl_quote(s):
    return '"' + s.replace('"', '""') + '"'

def api(user, privs, path, method="GET", body=None):
    run = 'ap %s %s "%s" "%s"' % (user, privs, path, method)
    if body is not None:
        run += " " + dcl_quote(json.dumps(body, separators=(",", ":")))
    out = vms(AP, 'define/nolog API_PROBE_PCSI_HELPER "%sSTEWARD_PCSI.COM"' % STAGE,
              'define/nolog API_PROBE_PCSI_JOB "%sSTEWARD_PCSI_JOB.COM"' % STAGE, run)
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    rest = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(rest[rest.index("{"):rest.rindex("}") + 1]) if "{" in rest else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def installed():
    out = vms("set process/privilege=syslck", "product show product STWDEMO /producer=ISSINOHO")
    return "STWDEMO" in out and not re.search(r"\b0 items found", out)

def follow(log, limit=600):
    """The job's log through Steward until its last line, or limit seconds."""
    t0 = time.time()
    doc = {}
    while time.time() - t0 < limit:
        st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/log?name=" + log)
        if st == 200 and doc and doc.get("done"):
            return doc
        time.sleep(10)
    return doc or {}

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

def login_dir(user):
    out = vms("set process/privilege=sysprv", "mcr authorize show %s /brief" % user)
    m = re.search(r"(\S+:)?(\[[^\]]+\])", out[out.find(user):] if user in out else "")
    dev = re.search(r"Default:\s+(\S+)", out)
    return dev.group(1) if dev else "SYS$SYSDEVICE:[%s]" % user

logs = []
ADMDIR = login_dir("STEWARD_ADM")
print("INFO STEWARD_ADM's login directory:", ADMDIR)
try:
    vms("create/directory/protection=(S:RWED,O:RWED,G:RE,W:RE) " + STAGE,
        "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR",
        "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_pcsi.com,steward_pcsi_job.com " + STAGE,
        "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.stwdemo.kit]*.pcsi " + STAGE,
        "create/directory/protection=(S:RWED,O:RWED,G:RE,W:RE) " + DEST)
    check(not installed(), "the demo product is not installed to begin with")

    st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/kits?source=" + STAGE)
    kits = (doc or {}).get("kits", [])
    check(st == 200 and [(k["name"], k["version"]) for k in kits] == [("STWDEMO", "V1.0")],
          "PRODUCT FIND through Steward: the demo kit in the staging directory", (st, doc))
    st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/kits?source=" + WORKDIR[:-1] + ".BUILD]")
    check(st == 200 and doc.get("kits") == [] and "NOMATCH" in doc.get("message", ""), "a directory without kits: PRODUCT's NOMATCH", (st, doc))

    st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/remove", "POST", {"producer": "VSI", "base": BASE, "name": "VMS"})
    check(st == 409, "the operating system: refused by Steward, nothing submitted", (st, doc))

    st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/install", "POST",
                  dict(DEMO, version="V1.0", source=STAGE, destination=DEST))
    check(st == 202 and doc.get("entry") and re.fullmatch(r"STEWARD_PCSI_\d{14}\.LOG", doc.get("log", "")),
          "install submitted: entry %s, log %s" % ((doc or {}).get("entry"), (doc or {}).get("log")), (st, doc))
    if st == 202:
        logs.append(doc["log"])
        st2, job = api("STEWARD_ADM", PRIVS, "/api/v1/jobs/%d" % doc["entry"])
        print("INFO job:", st2, json.dumps(job)[:300] if job else "")
        res = follow(doc["log"])
        print("INFO log:\n    " + "\n    ".join(res.get("lines", [])[-30:]))
        check(res.get("done") and res.get("success"), "the job ran to its end, successfully (%s)" % res.get("status"), res.get("status"))
        check(installed(), "PRODUCT SHOW PRODUCT now lists STWDEMO")
        files = vms("directory/nohead/notrail %s.STWDEMO]README.TXT" % DEST[:-1])
        check("README.TXT" in files, "its file in the destination", files[:200])

        st, doc = api("STEWARD_ADM", PRIVS, "/api/v1/products/remove", "POST", DEMO)
        check(st == 202 and doc.get("entry"), "removal submitted: entry %s" % (doc or {}).get("entry"), (st, doc))
        if st == 202:
            logs.append(doc["log"])
            res = follow(doc["log"])
            print("INFO log:\n    " + "\n    ".join(res.get("lines", [])[-20:]))
            check(res.get("done") and res.get("success"), "the removal ran to its end, successfully (%s)" % res.get("status"))
            check(not installed(), "PRODUCT SHOW PRODUCT no longer lists STWDEMO")
finally:
    if installed():
        print("WARNING: STWDEMO is still installed; removing it as the work account")
        vms("set process/privilege=(syslck,sysprv)", "product remove STWDEMO /producer=ISSINOHO /options=noconfirm", timeout=600)
    vms("set process/privilege=sysprv",
        *["delete/nolog %s%s;*" % (ADMDIR, l) for l in logs],
        "delete/nolog %s.STWDEMO]*.*;*" % DEST[:-1],
        "set security/protection=(O:RWED) %sSTWDEMO.DIR;1" % DEST,
        "delete/nolog %sSTWDEMO.DIR;1" % DEST,
        "delete/nolog %s*.*;*" % STAGE,
        "set security/protection=(O:RWED) %sDEST.DIR;1" % STAGE,
        "delete/nolog %sDEST.DIR;1" % STAGE,
        "delete/nolog %s*.*;*" % STAGE,
        "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR",
        "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR;*")
    check(not installed(), "the demo product is not installed at the end")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
