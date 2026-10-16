#!/usr/bin/env bash
# audit_rules.sh - project-specific security rules no general tool knows (D8).
#
# Each rule guards a property docs/security.md depends on. A hit fails the run; a
# deliberate exception goes in the rule's allow pattern with a comment saying why.
set -uo pipefail
cd "$(dirname "$0")/.."
fail=0

rule() {   # rule <name> <why> <grep -nE args...>
    local name=$1 why=$2; shift 2
    local hits
    # Comment lines (//, /*, *, #) may name a forbidden thing to explain why.
    hits=$(grep -rnE "$@" 2>/dev/null | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|/\*|\*|#)' || true)
    if [ -n "$hits" ]; then
        echo "AUDIT-RULE $name: $why"
        echo "$hits" | sed 's/^/    /'
        fail=1
    fi
}

# Text from OpenVMS (owner names, identifiers, messages) reaches the page; it must
# only ever go in as text. dom.js builds elements without HTML on purpose.
rule no-html-sinks "HTML sinks in the front end (use dom.js h())" \
    'innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function\(' www/

# A memset that clears a secret before free or return is a dead store the optimizer
# may delete; st_zero() cannot be removed.
rule scrub-with-st_zero "memset used to clear a secret (use st_zero)" \
    'memset\([^,]*(pw|pass|password|token|secret|csrf)' src/

# Personas are begun and ended in exactly one place, the dispatcher, so every path
# out of a handler ends the persona (D2).
rule persona-only-in-dispatcher "persona begin/end outside st_app.c" \
    --include='*.c' 'st_plat_persona_(begin|end)\(' src/svc src/core src/main \
    --exclude=st_app.c

# Configuration is read in one place, where its defaults are documented.
rule env-only-in-main "getenv outside steward_main.c" \
    --include='*.c' 'getenv\(' src/core src/svc src/plat

# The D14 helper procedure is fixed in the server. Only the test probe may swap it,
# to run an edited procedure before it is installed.
rule lnm-helper-test-only "st_plat_vms_test_helper, _sysgen, _license or _product called outside tests/" \
    --include='*.c' 'st_plat_vms_test_(helper|sysgen|license|product)\(' src/ --exclude=st_plat_vms.c
rule service-account-test-only "st_plat_vms_test_svc_* called outside tests/" \
    --include='*.c' 'st_plat_vms_test_svc_[a-z]+\(' src/ --exclude=st_plat_vms.c

# The core does no I/O (vmsguard's rule), which is what makes it testable and
# fuzzable on Linux.
rule core-no-io "I/O in src/core" \
    --include='*.c' '\b(fopen|fwrite|fprintf|printf|puts|recv|send|socket|open|read|write)\(' src/core

# No real node details or credentials in committed files (CLAUDE.md).
rule no-node-details "real node details" \
    --exclude-dir=.git --exclude-dir=build --exclude-dir=cache --exclude-dir=out --exclude=nodes.conf \
    --exclude=audit_rules.sh '192\.168\.[0-9]+\.[0-9]+|DISK\$SYSDUMP' .

# Every file the browser loads, and the procedures the service runs, are in the kit:
# the PCSI description and MAKE_KIT list them by name (0.4.0 was nearly packaged
# without access.js).
for f in www/js/*.js www/css/*.css vms/steward_lnm.com vms/steward_sysgen.com vms/steward_license.com vms/steward_pool.com; do
    n=$(basename "$f" | tr '[:lower:]' '[:upper:]')
    if ! grep -q "\]$n ;" 'kit/steward.pcsi$desc_template' || ! grep -qi "$n" kit/make_kit.com; then
        echo "AUDIT-RULE kit-has-files: $f is not in the kit"
        fail=1
    fi
done

if [ $fail -eq 0 ]; then echo "audit_rules: all rules pass"; fi
exit $fail
