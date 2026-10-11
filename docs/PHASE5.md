# Phase 5: hardening

The plan's Phase 5 (PLAN.md) covers several things. Most were done as the earlier
phases went: the kit and startup (0.1.0), idle and absolute session expiry (Phase 1),
the security headers, CSP, cookie flags and input limits (Phases 1 to 3), and the
README status table. Three things remained: a load run, a security review of what
changed since, and the outside review and penetration test (D8).

## Load run

`tests/load/load.py` drives Steward with concurrent clients doing what a browser
does: who am I, the dashboard as a background poll, users, a user, identifiers,
holders, access history, switching privileges on and off. They also send what an
attacker would:
- no session, or a forged cookie;
- no CSRF token, or a foreign Origin;
- malformed JSON, a long name, a body over the 256 KB limit;
- a NUL in a name, a path traversal, a bad time.

Every answer must be the status expected; a 5xx, a dropped connection or a wrong
status fails the run. It changes nothing.

**Linux, the real binary on the stub platform, over FastCGI (2026-10-11):**

| Build | Clients | Time | Requests | Failures | Notes |
|---|---|---|---|---|---|
| ASan/UBSan | 8 | 180s | 243,065 | 0 | no sanitizer report |
| plain | 8 | 180s | 353,552 | 0 | resident memory 7.7 MB after warm-up, 7.2 MB at the end |

**OpenVMS x86, the real dispatcher, personas and files, without lighttpd**
(`API_PROBE_SOAK=n tests/vms/api_probe`, every read-only endpoint n times over,
access history included):

| As | Requests | Page file in use (start → end) | Open files left (start → end) | Persona left active |
|---|---|---|---|---|
| STEWARD_ADM, SYSPRV on | 2,000 | 22064 → 22064 | 993 → 993 | never |
| STEWARD_TEST, no privileges | 2,000 | 21776 → 21776 | 993 → 993 | never |
| STEWARD_ADM, SYSPRV on | 10,000 (11m 34s) | 22064 → 22064 | 993 → 993 | never |
| STEWARD_ADM, after the review fixes | 2,000 | 22240 → 22240 | 993 → 993 | never |

**Through lighttpd** (`tests/load/load.py http http://<node>:8443 <user>`, password
from `STEWARD_LOAD_PASSWORD`). Steward shares the live board's lighttpd on the x86
node, so the user agreed to a short run and ran it from their own terminal, keeping
the password to themselves. Each client signs in once and reuses its session, so
OpenVMS's break-in detection is not provoked.

- **The first attempt** got 403 on all four sign-ins. STEWARD_TEST's password had
  expired, and Steward refused as designed: Steward's log has `outcome="expired"`, and
  that answer only comes with the right password. The script now prints the reason
  with a failed sign-in.
- **The second attempt**, after the password was changed: 4 clients for 120s as
  STEWARD_TEST, 3,772 requests, 0 failures. By status: 200 1,385; 201 4; 204 4;
  400 548; 401 354; 403 778; 404 343; 413 178; 422 178.

## Review

The Phase 6 code (access history: binary parsing of accounting and journal records,
log files, the merge) was reviewed line by line against the checklist in
security.md. Three findings, all fixed:
- a quadratic insert when the process table was full;
- an over-long record that ended the read of the whole file;
- RMS's search context left open on an early exit.

They are in security.md's audit record. Not found: unchecked lengths or offsets, an
unbounded copy, a string reaching the page other than as text.

**Still to do (the user's):**
- An independent review of the changed code, e.g. `/security-review`.
- The external review and penetration test, for which `REVIEW-BRIEF.md` is the brief.
