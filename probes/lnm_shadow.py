"""lnm_shadow.py - can an outer-mode or group-table name redirect the D14 helper?

    python3 probes/lnm_shadow.py [node]     (from the repo top, after @BUILD_VMS)

The helper procedure's path is translated when the helper process opens it, not in
the pool. So which names count: only executive-mode ones (LOGINOUT opens its input in
executive mode), or also user and supervisor names, in the system table or in a group
table (the service's or the viewer's)?

Method: [STEWARD_TEST.SHADOW.REAL] holds the real STEWARD_LNM.COM, [...SHADOW.FAKE] a
procedure that exits at once. STW_PROBE_ROOT is an executive-mode system name for REAL, and api_probe
uses STW_PROBE_ROOT:STEWARD_LNM.COM as the helper (API_PROBE_LNM_HELPER). Each case
adds one decoy STW_PROBE_ROOT for FAKE: a 200 means the real procedure ran, a quick
500 means the decoy was used. WRITES the name STW_PROBE_ROOT (system table, the work
account's group table and group 362's), and deletes it and [STEWARD_TEST.SHADOW] at the end."""
import re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
TOP = WORKDIR[:-1]
# Under STEWARD_TEST's own directory: the helper runs as STEWARD_TEST, and the work
# directory's parents are not open to it.
BASE = "SYS$SYSDEVICE:[STEWARD_TEST"
REAL, FAKE = BASE + ".SHADOW.REAL]", BASE + ".SHADOW.FAKE]"

def vms(*cmds):
    return subprocess.run(["tools/vms.sh", NODE, "dcl"] + list(cmds), capture_output=True,
                          encoding="latin-1").stdout.replace("\r", "")

def listing():
    out = vms('ap = "$' + TOP + '.BUILD]API_PROBE.EXE"',
              'define/nolog API_PROBE_LNM_HELPER "STW_PROBE_ROOT:STEWARD_LNM.COM"',
              'ap STEWARD_TEST - "/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=SYS$SYSROOT"')
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    if not m or m.group(1) != "200":
        print("   ", out.strip()[-300:].replace("\n", " | "))
    return int(m.group(1)) if m else None

def mygroup():
    out = vms('write sys$output f$fao("!6OW", f$getjpi("", "GRP"))')
    return "LNM$GROUP_" + out.strip().splitlines()[-1].strip()

CLEAN = ["deassign/system/user_mode STW_PROBE_ROOT", "deassign/system/supervisor_mode STW_PROBE_ROOT"]

try:
    group = mygroup()
    for t in (group, "LNM$GROUP_000362"):
        CLEAN += ["deassign/table=%s/user_mode STW_PROBE_ROOT" % t, "deassign/table=%s/supervisor_mode STW_PROBE_ROOT" % t]
    vms("create/directory/protection=(W:RE) " + REAL, "create/directory/protection=(W:RE) " + FAKE,
        "set security/protection=(W:RE) " + BASE + "]SHADOW.DIR",
        "copy [.vms]steward_lnm.com " + REAL + "/protection=(W:RE)")
    vms("open/write f " + FAKE + "STEWARD_LNM.COM", 'write f "$ exit"', "close f",
        "set security/protection=(W:RE) " + FAKE + "STEWARD_LNM.COM",
        "define/system/executive_mode STW_PROBE_ROOT " + REAL)
    base = listing()
    print("baseline, the executive-mode system name only:", base)
    if base != 200:
        raise SystemExit("the real procedure did not run: the probe proves nothing")
    for where, mode, define in (
            ("system table", "user", "define/system/user_mode"),
            ("system table", "supervisor", "define/system/supervisor_mode"),
            ("the service's group table (%s)" % group, "user", "define/table=%s/user_mode" % group),
            ("the service's group table (%s)" % group, "supervisor", "define/table=%s/supervisor_mode" % group),
            ("the viewer's group table (LNM$GROUP_000362)", "user", "define/table=LNM$GROUP_000362/user_mode"),
            ("the viewer's group table (LNM$GROUP_000362)", "supervisor", "define/table=LNM$GROUP_000362/supervisor_mode")):
        vms(define + " STW_PROBE_ROOT " + FAKE)
        st = listing()
        print("decoy at %s mode in %s: %s (%s)" % (mode, where, st, "the real procedure ran" if st == 200 else "SHADOWED"))
        vms(*CLEAN)
finally:
    vms(*(CLEAN + ["deassign/system/executive_mode STW_PROBE_ROOT"]))
    vms("set security/protection=(O:RWED) " + BASE + ".SHADOW...]*.*;*",
        "delete/nolog " + BASE + ".SHADOW...]*.*;*", "delete/nolog " + BASE + ".SHADOW...]*.*;*",
        "set security/protection=(O:RWED) " + BASE + "]SHADOW.DIR", "delete/nolog " + BASE + "]SHADOW.DIR;*")
    print("left:", vms("show logical/table=* STW_PROBE_ROOT").strip()[-200:])
