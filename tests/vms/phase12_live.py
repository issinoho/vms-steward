"""phase12_live.py - Phase 12 on a VMS node: installed products through the real
dispatcher and platform (tests/vms/api_probe), checked against PRODUCT SHOW and
VMSINSTAL.HISTORY.

    python3 tests/vms/phase12_live.py [node]      (default x86; run from the repo top)

READ-ONLY. With PHASE12_HELPER unset it stages vms/steward_product.com under
[STEWARD_TEST.P12T] (the helper runs as the viewer, who must read it) and removes it
after; with PHASE12_HELPER=installed it uses STEWARD$ROOT:[COM]STEWARD_PRODUCT.COM.
STEWARD_ADM must be authorized for SYSLCK (not by default). The reference listings
are the commands run by the work account, read with a parser of the test's own."""
import json, os, re, subprocess, sys

NODE = sys.argv[1] if len(sys.argv) > 1 else "x86"
with open("tools/nodes.conf") as f:
    WORKDIR = next(l.split()[5] for l in f if l.split() and l.split()[0] == NODE)
BUILD = WORKDIR[:-1] + ".BUILD]"
AP = 'ap = "$' + BUILD + 'API_PROBE.EXE"'
STAGE = "SYS$SYSDEVICE:[STEWARD_TEST.P12T]"
INSTALLED = os.environ.get("PHASE12_HELPER") == "installed"
HELPER = None if INSTALLED else STAGE + "STEWARD_PRODUCT.COM"
PRIVCLASS1 = "%X0652800A"

def vms(*cmds):
    return subprocess.run(["timeout", "300", "tools/vms.sh", NODE, "dcl"] + list(cmds), stdout=subprocess.PIPE,
                          encoding="latin-1").stdout.replace("\r", "")

def api(user, privs, path):
    pre = ['define/nolog API_PROBE_PRODUCT_HELPER "%s"' % HELPER] if HELPER else []
    out = vms(*([AP] + pre + ['ap %s %s "%s"' % (user, privs, path)]))
    m = re.search(r"^(\d{3})\s*$", out, re.M)
    body = out[m.end():].replace("\n", "") if m else ""
    try:
        doc = json.loads(body[body.index("{"):]) if "{" in body else None
    except ValueError:
        doc = None
    return (int(m.group(1)) if m else None), doc

def rows(listing):
    """The product of each row between the second and third dashed rules: its first
    four words."""
    out, rules = [], 0
    for line in listing.split("\n"):
        if re.match(r"^-+( -+)*\s*$", line):
            rules += 1
            continue
        if rules == 2 and line[:1] not in ("", " "):
            out.append(" ".join(line.split()[:4]))
    return out

def reference():
    products = rows(vms("set process/privilege=syslck", "product show product/full"))
    history = rows(vms("set process/privilege=syslck", "product show history/full"))
    runs = [l for l in vms("type SYS$UPDATE:VMSINSTAL.HISTORY").split("\n")
            if l.count("|") == 8 and re.search(r"\|\s*\d{1,2}-[A-Z]{3}-\d{4}\s*\|", l)]
    return products, history, [l.split("|")[1].strip() for l in runs]

ok = bad = 0
def check(cond, what, extra=""):
    global ok, bad
    if cond:
        ok += 1; print("ok  ", what)
    else:
        bad += 1; print("FAIL", what, extra)

def name(p):
    return " ".join((p["producer"], p["base"], p["name"], p["version"]))

try:
    if HELPER:
        vms("create/directory/protection=(S:RWED,O:RWED,G:RE,W:RE) " + STAGE,
            "set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR",
            "copy/protection=(S:RWED,O:RWED,G:RE,W:RE) [.vms]steward_product.com " + STAGE)
    products, history, runs = reference()
    check(len(products) > 0 and len(history) > 0,
          "PRODUCT SHOW lists %d products, %d history entries; VMSINSTAL %d runs" % (len(products), len(history), len(runs)))

    st, doc = api("STEWARD_TEST", "-", "/api/v1/products")
    doc = doc or {}
    src = doc.get("sources", {})
    check(st == 200 and not src.get("products", {}).get("read") and src.get("products", {}).get("vms_status") == PRIVCLASS1
          and "SYSLCK" in src.get("products", {}).get("vms_message", "") and doc.get("products") == [] and doc.get("history") == [],
          "STEWARD_TEST (no SYSLCK): PCSI refused as PRODUCT SHOW refuses it (PRIVCLASS1), and nothing of it shown",
          (st, src))
    check(src.get("vmsinstal", {}).get("read") and [v["mnemonic"] for v in doc.get("vmsinstal", [])] == runs,
          "and VMSINSTAL's history, the same runs in order (%d)" % len(doc.get("vmsinstal", [])),
          ([v["mnemonic"] for v in doc.get("vmsinstal", [])], runs))

    st, doc = api("STEWARD_ADM", "SYSLCK", "/api/v1/products")
    doc = doc or {}
    ours = [name(p) for p in doc.get("products", [])]
    check(st == 200 and doc.get("sources", {}).get("products", {}).get("read") and ours == products,
          "STEWARD_ADM with SYSLCK: the same products, in order (%d)" % len(ours),
          (st, doc.get("sources"), sorted(set(ours) ^ set(products))[:6]))
    check([name(p) for p in doc.get("history", [])] == history,
          "and the same history (%d)" % len(doc.get("history", [])),
          sorted(set(name(p) for p in doc.get("history", [])) ^ set(history))[:6])
    check(doc.get("products") and all(p["kit_type"] and p["state"] for p in doc["products"]),
          "every product with its kit type and state")

    # Does PRODUCT SHOW need SYSLCK switched on, or only authorized (NOTES.md)? Shown,
    # not checked, until it is settled.
    st, doc = api("STEWARD_ADM", "-", "/api/v1/products")
    s = ((doc or {}).get("sources") or {}).get("products", {})
    print("INFO STEWARD_ADM, SYSLCK authorized but not switched on: PCSI %s" %
          ("read" if s.get("read") else "refused, %s" % s.get("vms_message", s)))

    left = vms('pipe show system | search sys$pipe "STW"')
    check("STW" not in left.replace("search sys$pipe", ""), "no helper process left behind", left[-200:])
finally:
    if HELPER:
        vms("set security/protection=(S:RWED,O:RWED) %s*.*;*" % STAGE, "delete/nolog %s*.*;*" % STAGE,
            "set security/protection=(S:RWED,O:RWED) SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR",
            "delete/nolog SYS$SYSDEVICE:[STEWARD_TEST]P12T.DIR;*")

print("%d ok, %d failed" % (ok, bad))
sys.exit(1 if bad else 0)
