"""phase11_live.py - Phase 11 on a VMS node: licences through the real dispatcher and
platform (tests/vms/api_probe), checked against SHOW LICENSE and LICENSE LIST.

    python3 tests/vms/phase11_live.py [node]      (default x86; run from the repo top)

READ-ONLY. With PHASE11_HELPER unset it stages vms/steward_license.com under
[STEWARD_TEST.P11T] (the helper runs as the viewer, who must read it) and removes it
after; with PHASE11_HELPER=installed it uses STEWARD$ROOT:[COM]STEWARD_LICENSE.COM. The
reference listings are the commands run by the work account, read with a parser of the
test's own. Authorization numbers are compared, never printed."""
import json, os, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P11T]"
INSTALLED = os.environ.get("PHASE11_HELPER") == "installed"
HELPER = None if INSTALLED else STAGE + "STEWARD_LICENSE.COM"

def vms(*cmds):
    return subprocess.run(["timeout", "180", "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path):
    pre = ['define/nolog API_PROBE_LICENSE_HELPER "%s"' % HELPER] if HELPER else []
    out = vms(*([AP] + pre + ['ap %s %s "%s"' % (user, privs, path)]))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def reference():
    """The work account's SHOW LICENSE/FULL (product names), the charge's last line, and
    LICENSE LIST/FULL ((product, authorization, status) for each PAK)."""
    out = vms("show license/full")
    loaded = re.findall(r"^([A-Z0-9][A-Z0-9_$.-]*)$", out.split("Active licenses on node", 1)[-1], re.M)
    charge = vms("show license/unit_requirements").strip().split("\n")[-1].strip()
    out = vms("license list/full")
    paks = []
    for block in out.split("-----------------------------------")[1:]:
        g = lambda k: (re.search(r"^%s:[ \t]*(.*)$" % k, block, re.M) or [None, ""])[1].strip()
        paks.append((g("Product Name"), g("Authorization"), g("Status")))
    return loaded, charge, paks

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
            "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P11T.DIR",
            "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_license.com " + STAGE)
    loaded, charge, paks = reference()
    check(len(loaded) > 0 and len(paks) > 0, "SHOW LICENSE lists %d, LICENSE LIST %d" % (len(loaded), len(paks)))

    st, doc = api("STEWARD_TEST", "-", "/api/v1/licenses")
    doc = doc or {}
    src = doc.get("sources", {})
    ours = [l["product"] for l in doc.get("loaded", [])]
    check(st == 200 and ours == loaded, "STEWARD_TEST: the same loaded licences, in order (%d)" % len(ours),
          (st, ours, loaded, doc if st != 200 else ""))
    check(src.get("loaded", {}).get("read") and src.get("charge", {}).get("read") and
          (doc.get("charge", {}).get("lines") or [""])[-1] == charge, "and the same charge", doc.get("charge"))
    db = src.get("database", {})
    check(not db.get("read") and db.get("vms_status") == "%X0001829C" and doc.get("database") == [] and
          "privilege" in db.get("vms_message", ""),
          "the database refused as LICENSE LIST refuses it (RMS-F-PRV), and nothing of it shown",
          {k: v for k, v in db.items()})

    st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/licenses")
    doc = doc or {}
    ours = [(l["product"], l["authorization"], l["status"]) for l in doc.get("database", [])]
    check(st == 200 and doc.get("sources", {}).get("database", {}).get("read") and ours == paks,
          "STEWARD_ADM with SYSPRV: the same PAKs, authorizations and statuses as LICENSE LIST (%d)" % len(ours),
          (st, [p[0] for p in ours], [p[0] for p in paks]))
    check("LMF$LICENSE.LDB" in doc.get("database_file", {}).get("file", ""), "the database file", doc.get("database_file"))
    check([l["product"] for l in doc.get("loaded", [])] == loaded, "and the loaded licences still")

    st, doc = api("STEWARD_ADM", "-", "/api/v1/licenses")
    check(st == 200 and not (doc or {}).get("sources", {}).get("database", {}).get("read"),
          "STEWARD_ADM with SYSPRV authorized but not switched on: refused (D9)")
    left = vms('pipe show system | search sys$pipe "STW"')
    check("STW" not in left.replace("search sys$pipe", ""), "no helper process left behind", left[-200:])
finally:
    if HELPER:
        vms("set security/protection=(S:RWED,O:RWED) %s*.*;*" % STAGE, "delete/nolog %s*.*;*" % STAGE,
            "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P11T.DIR",
            "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P11T.DIR;*")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
