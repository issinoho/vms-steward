"""phase7_live.py - Phase 7 (7a) on a VMS node: logical names through the real
dispatcher and platform (tests/vms/api_probe), checked against SHOW LOGICAL.

    python3 tests/vms/phase7_live.py [node]      (default x86; run from the repo top)

READ-ONLY: it lists and translates logical names; it defines nothing. The helper
procedure must be at STEWARD$ROOT:[COM]STEWARD_LNM.COM (the kit puts it there). Needs
@BUILD_VMS run on the node first; the node's paths come from tools/nodes.conf.

    PHASE7_HELPER=dev:[dir]STEWARD_LNM.COM   test that procedure instead of the
        installed one (API_PROBE_LNM_HELPER); STEWARD_TEST must be able to read it.
    PHASE7_FAILDIR=dev:[dir]   also run LNM_DEAD.COM and LNM_FLOOD.COM (probes/) from
        there, as helpers that die at once and that flood the reply mailbox."""
import json, os, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
VMS = ["tools/vms.sh", NODE, "dcl"]
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
AP = 'ap = "$' + WORKDIR[:-1] + '.BUILD]API_PROBE.EXE"'

def vms(*cmds):
    # Latin-1: logical names may hold any byte (the node's system table has a 0xC0)
    return subprocess.run(VMS + list(cmds), capture_output=True, encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path, helper=os.environ.get("PHASE7_HELPER"), timed=False):
    pre = ['define/nolog API_PROBE_LNM_HELPER "%s"' % helper] if helper else []
    run = ['ap %s %s "%s"' % (user, privs, path)]
    if timed:   # on the node: ssh and the network vary by seconds
        run = ['t0 = f$cvtime(,,"SECONDOFYEAR")'] + run + \
              ['write sys$output "TOOK ", f$cvtime(,,"SECONDOFYEAR") - t0']
    out = vms(*([AP] + pre + run))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    took = re.search(r"^TOOK (\d+)", out, re.M)
    if took:
        body = body[:body.rindex("TOOK")]
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    if timed:
        return (int(m.group(1)) if m else None), doc, (int(took.group(1)) if took else None)
    return (int(m.group(1)) if m else None), doc

def show_names(table, pattern="*", privs=""):
    """Names SHOW LOGICAL lists, run here (a privileged work account)."""
    pre = ["set process/privilege=(%s)" % privs] if privs else []
    out = vms(*(pre + ["show logical/full/table=%s %s" % (table, pattern)]))
    return set(re.findall(r'^  "([^"]+)" \[', out, re.M))

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

def names(doc):
    return {n["name"] for t in (doc or {}).get("tables", []) for n in t["names"]}

st, doc = api("STEWARD_TEST", "-", "/api/v1/logicals/tables")
tables = {t["name"]: t for t in (doc or {}).get("tables", [])}
check(st == 200 and "LNM$SYSTEM_TABLE" in tables and doc["your_group_table"] == "LNM$GROUP_000362",
      "the tables, and STEWARD_TEST's own group table named", (st, doc and list(tables)[:5]))
check(all(not n.startswith("LNM$PROCESS") for n in tables), "no process table among them")
jobs = [n for n in tables if n.startswith("LNM$JOB_")]
check(jobs and not any(tables[n]["listable"] for n in jobs), "job tables are shown, none listable (%d)" % len(jobs))

# SHOW LOGICAL/STRUCTURE nests each table under its parent (the table its quota comes
# from), so compare the names under LNM$SYSTEM_DIRECTORY, at any depth. Two differences
# are expected: the directory lists itself, and job tables come and go (the helper's
# own job, this script's).
structure, inside = set(), False
for l in vms("show logical/structure").splitlines():
    m = re.match(r"^( *)\((.+)\)\s*$", l)
    if not m:
        continue
    if not m.group(1):
        inside = m.group(2) == "LNM$SYSTEM_DIRECTORY"
    elif inside:
        structure.add(m.group(2))
diff = (set(tables) - {"LNM$SYSTEM_DIRECTORY"}) ^ structure
check(len(structure) > 10 and all(n.startswith("LNM$JOB_") for n in diff) and len(diff) <= 6,
      "the tables as SHOW LOGICAL/STRUCTURE lists them: %d here, %d there, child tables too, %d job tables differ"
      % (len(tables), len(structure), len(diff)), sorted(diff)[:8])

st, doc = api("STEWARD_TEST", "-", "/api/v1/logicals?table=LNM$SYSTEM_TABLE")
ours, theirs = names(doc), show_names("LNM$SYSTEM_TABLE")
check(st == 200 and len(ours) > 100 and len(ours ^ theirs) <= 3,
      "the system table as SHOW LOGICAL lists it: %d names here, %d there" % (len(ours), len(theirs)),
      sorted(ours ^ theirs)[:6])
sysroot = next((n for t in doc["tables"] for n in t["names"] if n["name"] == "SYS$SYSROOT"), None) if doc else None
trn = vms('write sys$output f$trnlnm("SYS$SYSROOT","LNM$SYSTEM_TABLE",0)', 'write sys$output f$trnlnm("SYS$SYSROOT","LNM$SYSTEM_TABLE",1)')
want = [l.strip() for l in trn.splitlines() if l.strip()][-2:]
check(sysroot and [e["value"] for e in sysroot["equivalences"]] == want and "concealed" in sysroot["equivalences"][0]["attributes"],
      "SYS$SYSROOT: both equivalences as F$TRNLNM gives them, with their attributes", (sysroot, want))

st, doc = api("STEWARD_TEST", "-", "/api/v1/logicals/LNM$SYSTEM_TABLE/SYS$SYSROOT")
check(st == 200 and doc["translations"][1] and doc["translations"][1][0]["name"] == "SYS$COMMON",
      "one name, in-process, and SYS$COMMON: translated in turn", doc and doc.get("translations"))

st, doc = api("STEWARD_TEST", "-", "/api/v1/logicals?table=LNM$GROUP")
check(st == 200 and all(t["name"] == "LNM$GROUP_000362" for t in doc["tables"]),
      "LNM$GROUP is STEWARD_TEST's own group table", doc)
st, doc = api("STEWARD_TEST", "-", "/api/v1/logicals?table=LNM$GROUP_000001")
check(st == 404 and "IVLOGTAB" in json.dumps(doc), "another group's table: refused as SHOW LOGICAL refuses (IVLOGTAB)", (st, doc))
st, doc = api("STEWARD_ADM", "-", "/api/v1/logicals?table=LNM$GROUP_000001")
check(st == 404, "STEWARD_ADM without SYSPRV switched on: refused too", (st, doc))
st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/logicals?table=LNM$GROUP_000001")
ours, theirs = names(doc), show_names("LNM$GROUP_000001", privs="SYSPRV")
check(st == 200 and ours == theirs and ours,
      "with SYSPRV switched on (D9), the helper has it too: group 1's %d names, as SHOW LOGICAL" % len(ours),
      sorted(ours ^ theirs)[:6])

for path, what in (("/api/v1/logicals?table=LNM$PROCESS", "the process table"),
                   ("/api/v1/logicals?table=LNM$FILE_DEV", "a search list through the process table"),
                   ("/api/v1/logicals/LNM$PROCESS_TABLE/STEWARD_GATEWAY_SECRET", "the gateway secret by name"),
                   ("/api/v1/logicals?table=LNM$SYSTEM_TABLE/OUTPUT=X", "a table with a qualifier in it"),
                   ("/api/v1/logicals?table=LNM$SYSTEM_TABLE&filter=A%27B", "a pattern with a quote"),
                   ("/api/v1/logicals?table=" + (jobs[0] if jobs else "LNM$JOB_0"), "a job table by its own name"),
                   ("/api/v1/logicals/%s/X" % (jobs[0] if jobs else "LNM$JOB_0"), "one name in a job table")):
    st, doc = api("STEWARD_ADM", "SYSPRV", path)
    check(st == 400 and "secret" not in json.dumps(doc).lower(), "refused before OpenVMS is asked: " + what, (st, doc))

st, doc = api("STEWARD_ADM", "SYSPRV", "/api/v1/logicals/LNM$SYSTEM_DIRECTORY/LNM$FILE_DEV")
check(st == 404, "a single-name lookup only in a real table, never a directory or search list", (st, doc))

FAIL = os.environ.get("PHASE7_FAILDIR")
if FAIL:
    # The termination mailbox: a helper that ends without answering is noticed at
    # once (plus the 2 s grace), not at the 30 s deadline.
    st, doc, took = api("STEWARD_TEST", "-", "/api/v1/logicals?table=LNM$SYSTEM_TABLE", FAIL + "LNM_DEAD.COM", timed=True)
    check(st == 500 and took is not None and took <= 5,
          "a helper that ends without answering: an error in %ss on the node, not 30" % took, (st, doc))
    # The deadline holds whatever wakes the reader: a helper that keeps the reply
    # mailbox full is stopped at 30 s and deleted.
    st, doc, took = api("STEWARD_TEST", "-", "/api/v1/logicals?table=LNM$SYSTEM_TABLE", FAIL + "LNM_FLOOD.COM", timed=True)
    check(st == 500 and "TIMEOUT" in json.dumps(doc) and took is not None and 29 <= took <= 33,
          "a helper that floods the mailbox: stopped at the deadline (%ss on the node)" % took, (st, doc))

left = vms('pipe show system | search sys$pipe "STW"')
check("STW" not in left.replace("search sys$pipe", ""), "no helper process left behind", left[-200:])
print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
