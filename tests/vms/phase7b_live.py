"""phase7b_live.py - Phase 7b on a VMS node: define and deassign through the real
dispatcher and platform (tests/vms/api_probe), checked against DCL.

    python3 tests/vms/phase7b_live.py [node]      (default x86; run from the repo top)

WRITES LOGICAL NAMES: the one name STEWARD_PROBE_7B, in LNM$SYSTEM_TABLE (as
STEWARD_ADM, which needs SYSNAM authorized) and in STEWARD_TEST's group table
(LNM$GROUP_000362, with GRPPRV), as the user agreed on 2026-10-13. Whatever happens it
deassigns that name from both tables at the end, as the work account. Needs @BUILD_VMS
run on the node first; the node's paths come from tools/nodes.conf."""
import json, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
VMS = ["tools/vms.sh", NODE, "dcl"]
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
AUDIT = BUILD + "PROBE_7B_AUDIT.LOG"
NAME, GROUP = "STEWARD_PROBE_7B", "LNM$GROUP_000362"

def vms(*cmds):
    return subprocess.run(VMS + list(cmds), capture_output=True, encoding="latin-1").stdout.replace("\r", "")

def dcl_quote(s):
    return '"' + s.replace('"', '""') + '"'

def api(user, privs, path, method="GET", body=None):
    run = 'ap %s %s "%s" "%s"' % (user, privs, path, method)
    if body is not None:
        run += " " + dcl_quote(json.dumps(body, separators=(",", ":")))
    out = vms(AP, 'define/nolog API_PROBE_AUDIT ' + AUDIT, run)
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    rest = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(rest[rest.index("{"):]) if "{" in rest else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def modes_in(table):
    """What DCL sees: {mode: [values]} for NAME in table, by F$TRNLNM at each mode."""
    cmds = []
    for mode in ("USER", "SUPERVISOR", "EXECUTIVE"):
        cmds.append('write sys$output "%s|", f$trnlnm("%s","%s",,"%s",,"ACCESS_MODE"), "|", '
                    'f$trnlnm("%s","%s",,"%s",,"VALUE"), "|", f$trnlnm("%s","%s",,"%s",,"MAX_INDEX")'
                    % (mode, NAME, table, mode, NAME, table, mode, NAME, table, mode))
    got = {}
    for l in vms(*cmds).splitlines():
        p = l.split("|")
        if len(p) == 4 and p[1] and p[0].startswith(p[1][:4]):   # found at exactly that mode
            got[p[1].lower()] = (p[2], p[3])
    return got

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

def define(user, privs, table, mode, values, replace=None, attrs=None):
    body = {"table": table, "name": NAME, "mode": mode,
            "equivalences": [v if isinstance(v, dict) else {"value": v} for v in values]}
    if replace is not None:
        body["replace"] = replace
    if attrs:
        body["attributes"] = attrs
    return api(user, privs, "/api/v1/logical", "PUT", body)

def deassign(user, privs, table, mode):
    return api(user, privs, "/api/v1/logical?table=%s&name=%s&mode=%s" % (table, NAME, mode), "DELETE")

try:
    vms("delete/nolog " + AUDIT + ";*")
    check(modes_in("LNM$SYSTEM_TABLE") == {} and modes_in(GROUP) == {}, "the name is in neither table to begin with")

    # ---- the group table, as STEWARD_TEST ----
    st, doc = define("STEWARD_TEST", "-", "LNM$GROUP", "user", ["A"])
    check(st == 403 and "NOPRIV" in json.dumps(doc) and modes_in(GROUP) == {},
          "STEWARD_TEST without GRPPRV: NOPRIV, as OpenVMS answers the persona", (st, doc))
    st, doc = define("STEWARD_TEST", "GRPPRV", "LNM$GROUP", "user",
                     [{"value": "X86VMS$DKA0:[P.]", "attributes": ["concealed", "terminal"]}, "SECOND"])
    show = vms("show logical/full/table=%s %s" % (GROUP, NAME))
    check(st == 201 and doc["table"] == GROUP and doc["modes"] == ["user"] and
          '"%s" [user] = "X86VMS$DKA0:[P.]" [concealed,terminal]' % NAME in show and '= "SECOND"' in show,
          "with GRPPRV: defined in its own group table, as SHOW LOGICAL/FULL shows it", (st, doc, show))
    st, doc = define("STEWARD_TEST", "GRPPRV", "LNM$GROUP", "exec", ["QUIET"])
    check(st == 403 and "NOSYSNAM" in json.dumps(doc) and modes_in(GROUP) == {"user": ("X86VMS$DKA0:[P.]", "1")},
          "exec mode without SYSNAM: refused, and the user-mode name is untouched (OpenVMS would have replaced it)",
          (st, doc, modes_in(GROUP)))
    st, doc = deassign("STEWARD_TEST", "GRPPRV", "LNM$GROUP", "exec")
    check(st == 403 and "user" in modes_in(GROUP), "nor deassigned at exec mode without SYSNAM", (st, doc))
    st, doc = deassign("STEWARD_TEST", "GRPPRV", "LNM$GROUP", "user")
    check(st == 200 and doc["removed"] == ["user"] and modes_in(GROUP) == {}, "deassigned from the group table", (st, doc))

    # ---- the system table, as STEWARD_ADM ----
    st, doc = define("STEWARD_ADM", "SYSPRV", "LNM$SYSTEM_TABLE", "exec", ["E"])
    check(st == 403 and "NOSYSNAM" in json.dumps(doc) and modes_in("LNM$SYSTEM_TABLE") == {},
          "SYSPRV alone, exec mode: refused before OpenVMS is asked", (st, doc))
    for mode, value in (("exec", "E"), ("super", "S"), ("user", "U")):
        st, doc = define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", mode, [value])
        check(st == 201, "with SYSNAM: defined at %s mode" % mode, (st, doc))
    got = modes_in("LNM$SYSTEM_TABLE")
    check(got == {"user": ("U", "0"), "supervisor": ("S", "0"), "executive": ("E", "0")} and
          doc["modes"] == ["user", "super", "exec"],
          "each mode its own name, as F$TRNLNM sees them, and the answer lists all three", (got, doc))
    st, doc = define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "super", ["S2"])
    check(st == 409 and modes_in("LNM$SYSTEM_TABLE")["supervisor"][0] == "S", "again without replace: 409, unchanged", (st, doc))
    st, doc = define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "super", ["S2"], replace=True)
    check(st == 200 and modes_in("LNM$SYSTEM_TABLE")["supervisor"][0] == "S2" and doc["modes"] == ["user", "super", "exec"],
          "with replace: 200, the supervisor-mode name replaced, the others kept", (st, doc))
    st, doc = deassign("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "super")
    check(st == 200 and doc["removed"] == ["user", "super"] and modes_in("LNM$SYSTEM_TABLE") == {"executive": ("E", "0")},
          "deassign at supervisor mode: it and the user-mode name go, as DEASSIGN does", (st, doc))
    # NO_ALIAS: $CRELNM deletes the name at every outer mode (NOTES.md).
    define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "user", ["U"])
    st, doc = define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "exec", ["E2"], replace=True, attrs=["no_alias"])
    show = vms("show logical/full/table=LNM$SYSTEM_TABLE %s" % NAME)
    check(st == 200 and doc["modes"] == ["exec"] and doc["logical"]["attributes"] == ["no_alias"] and
          modes_in("LNM$SYSTEM_TABLE") == {"executive": ("E2", "0")} and "[exec,no_alias]" in show,
          "no_alias at exec mode: OpenVMS removes the user-mode name, and the answer shows it", (st, doc, show))
    st, doc = deassign("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "exec")
    check(st == 200 and doc["removed"] == ["exec"] and modes_in("LNM$SYSTEM_TABLE") == {}, "and at executive mode", (st, doc))
    st, doc = deassign("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_TABLE", "exec")
    check(st == 404 and "NOLOGNAM" in json.dumps(doc), "deassigning what is gone: 404 NOLOGNAM", (st, doc))

    st, doc = define("STEWARD_ADM", "SYSPRV,SYSNAM", "LNM$SYSTEM_DIRECTORY", "exec", ["X"])
    check(st == 404, "never in the directory", (st, doc))
    st, doc = api("STEWARD_ADM", "SYSPRV,SYSNAM", "/api/v1/logical?table=LNM$SYSTEM_TABLE&name=SYS$SYSROOT")
    check(st == 200 and "exec" in doc["modes"], "one name by query, with its modes", (st, doc and doc.get("modes")))

    log = vms("type " + AUDIT)
    check('action="logical-define" target="LNM$SYSTEM_TABLE %s exec" outcome="ok"' % NAME in log and
          'action="logical-deassign" target="%s %s user" outcome="ok"' % (GROUP, NAME) in log and
          'outcome="failed" detail="%SYSTEM-F-NOPRIV' in log and "X86VMS$DKA0:[P.]" not in log and '"S2"' not in log,
          "audited on the node: changes and refusals, never an equivalence", log[-600:])
finally:
    vms("deassign/system/executive_mode " + NAME, "deassign/table=%s/executive_mode %s" % (GROUP, NAME),
        "delete/nolog " + AUDIT + ";*")
    left = vms("show logical/table=LNM$SYSTEM_TABLE " + NAME, "show logical/table=%s %s" % (GROUP, NAME))
    check(NAME + '"' not in left, "nothing left in either table", left)

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
