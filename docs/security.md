# Security: threat model and code audit programme

Steward lets a browser change who may log in to an OpenVMS system and with what
privileges. A bug in it is a privilege-escalation bug in the operating system, so
the code is audited continuously and at every phase gate (DECISIONS D8). This file
holds the threat model those audits work from, the checks that run, and the record
of what each audit found.

## Assets

1. **The authorization database** (SYSUAF, RIGHTSLIST) and everything it controls.
2. **Passwords** in transit through Steward (sign-in, later password changes).
3. **Sessions**: a session token is an authenticated OpenVMS identity for its
   lifetime.
4. **The service account's IMPERSONATE privilege**: with it, Steward can become any
   user without a password. Every check in D2 exists to keep that power on a leash.
5. **Intrusion detection** (D2): records must name the real client, or an attacker
   can hide, or lock everyone out.

## Trust boundaries

```
browser ─(1)─ nginx proxy manager ─(2)─ lighttpd ─(3)─ STEWARD.EXE ─(4)─ system services
                                                        (IMPERSONATE)     under a persona
```

1. Untrusted: everything from the browser, including headers it can set
   (`X-Forwarded-*`, `Origin`, cookies, JSON).
2. Proxy to lighttpd: trusted only for the proxies in `STEWARD_TRUSTED_PROXIES` (D7).
3. FastCGI over loopback: Steward refuses non-loopback peers, but still treats every
   byte as untrusted. The parsers are fuzzed.
4. The OS boundary: the persona makes OpenVMS do the authorization (D2). Steward's
   job is to get the *right* persona and to end it on every path.

## Attacker models

| Who | Can | Must not be able to |
|---|---|---|
| Local OpenVMS user | connect to 127.0.0.1, read world-readable files | reach the FastCGI ports directly and choose their own REMOTE_ADDR, which would let them guess passwords without triggering breakin evasion; read the session store or audit log |
| Anonymous on the network | send any HTTP, guess passwords | sign in without a password; probe which usernames exist; lock everyone out; hide behind the proxy's address |
| Signed-in unprivileged user | call any endpoint | do anything OpenVMS would refuse them at a terminal; act as another user; keep a session past logout or expiry |
| Malicious web page in the user's browser | make the browser send requests | ride the user's session (CSRF), read responses, frame Steward |
| Someone who can read a session store backup | read stored records | use them as live sessions (only token hashes are stored) |
| Someone who can write OpenVMS data Steward displays (owner fields, identifier names) | put markup or control characters there | inject into the page, the JSON, or the audit log |

## Security invariants (each is enforced and tested)

| Invariant | Enforced by | Tested by |
|---|---|---|
| Every request ends with no persona active | dispatcher; server exits if one leaks | unit `test_dispatch`, API suite |
| Personas begin and end only in the dispatcher | design | `audit_rules.sh persona-only-in-dispatcher` |
| The service's SYSPRV is on only around `$PERSONA_CREATE` (D2 amendment) | enabled and disabled around the call; process exits if it cannot disable; checked after every request | on VMS at the phase exit: `STEWARD_POOL STATUS` shows no SYSPRV |
| Only our lighttpd reaches the API (gateway secret) | dispatcher `via_gateway`; lighttpd overwrites the header | unit `test_gateway`; API "bypasses lighttpd"; on VMS, direct FastCGI 403 |
| Session store and audit log private to the service | pool default protection `(S:RWED,O:RWED,G,W)` and `[.RUN]` | directory listing at phase exit |
| A session can enable only privileges the user is authorized for (D9) | OpenVMS: `$SETPRV` under the persona is capped by the persona's authorized mask (probe_setprv); Steward also refuses unauthorized names up front | unit `test_privileges`; API "unauthorized privilege is refused" |
| Forwarded headers believed only from trusted proxies | `st_app_origin` | unit `test_proxy`, API "untrusted peer" |
| State changes need same origin and the session's CSRF token | dispatcher | unit and API suites |
| Sign-in failures are indistinguishable (wrong password, disabled, no such user, malformed) | `svc_session_login` | unit "disabled looks the same" |
| Expired passwords get no session | platform check after `$ACM` | unit, API, and on VMS at phase exit |
| Usernames are validated and upcased before `$ACM` or `$PERSONA_CREATE` | `st_valid_username` | unit |
| No password or token in logs, responses or freed memory | `st_zero`, `st_json_free` scrubbing | API "no password in the audit log"; `audit_rules.sh scrub-with-st_zero` |
| Data from OpenVMS never becomes markup | `dom.js` text nodes; JSON writer escapes `<>&`; CSP | `audit_rules.sh no-html-sinks`; unit writer test |
| Privilege masks carried as full quadwords | review | PHASE1 probe finding; review checklist |

## What runs, and when

**Every push (CI, `.github/workflows/ci.yml`) and `make audit` locally:**
- GCC `-fanalyzer` over every source file, warnings as errors.
- cppcheck (warning and portability classes) and flawfinder (level 4 and up).
- Semgrep with the C, JavaScript and secrets rule packs; gitleaks over the history.
- `tools/audit_rules.sh`: the project rules above, which no general tool knows.
- The API suite against an ASan/UBSan build, and 200,000 rounds of mutation fuzzing
  of the JSON and FastCGI parsers under ASan/UBSan.
- Strict compiler flags (`-std=c99 -pedantic -Wall -Wextra`), never weakened.

**At every phase exit (a gate: the phase does not close until it passes):**
1. Update this threat model for what the phase added: new endpoints, new system
   services, new data shown.
2. A line-by-line security review of every changed file against the checklist below,
   by someone other than the author of the change (for Claude-written code: the user,
   or an independent review run with `/security-review` and `/code-review`, with
   findings checked by hand).
3. The VMS-side checks no Linux tool can do: every LINK checked for `$SEVERITY`;
   image privileges and file protections listed and justified; the service
   account's privileges confirmed minimal (`SHOW PROCESS/PRIVILEGES` in the pool).
4. Findings recorded below with severity, fix commit and a regression test that
   fails without the fix.

**Before the first release (Phase 5):** an independent external review of the
authentication, session and persona code, and a penetration test of a staging
instance behind nginx proxy manager.

## Review checklist

- [ ] Every new input is bounded and validated before use (lengths, character sets,
      integer ranges), and refused rather than repaired.
- [ ] Every system-service call checks both the return status and the IOSB/ACMESB
      status. 64-bit masks are not truncated (`PRV$M_*` above bit 31).
- [ ] Every new handler path ends without assuming anything about persona state
      (the dispatcher ends it).
- [ ] No new error message tells an unauthenticated client which of several
      failures happened.
- [ ] Secrets are scrubbed with `st_zero` and never logged.
- [ ] Strings from OpenVMS reach the browser only through the JSON writer and
      `dom.js`.
- [ ] Item lists, descriptors and buffers are sized from the definitions, and every
      `retlen` is honoured.
- [ ] New dependencies: none without a decision in DECISIONS.md.
- [ ] Least-privilege claims are verified on the **success** path, run as the real
      service account (a failed sign-in never creates a persona: PHASE1.md).

## Audit record

| Date | Phase | Finding | Severity | Fix | Regression test |
|---|---|---|---|---|---|
| 2026-10-10 | 1 | Use-after-free: the malformed-login audit line read the username after the JSON document was freed and scrubbed | High (memory safety, pre-auth) | b99ac16 | API suite under ASan (`make api-test-asan`) |
| 2026-10-10 | 1 | `X-Forwarded-For` walk lost the hop after a trusted proxy, so a chain of proxies gave the wrong client address | Medium (intrusion records misattributed) | b99ac16 | unit `test_proxy` "a chain of trusted proxies", failed before the fix |
| 2026-10-10 | 1 | `make audit` ran `-fanalyzer` under `-fsyntax-only`, where it silently does nothing | Medium (audit gap) | this commit | planted double free is caught |
| 2026-10-10 | 1 | First CI run: flawfinder found 16 level-4 uses of `strcpy`/`strcat`/`sprintf` (each bounded in context, none exploitable as written) | Low (hardening) | this commit: `st_copy`/`st_append`/`snprintf`; the printf wrapper gets a GCC `format` attribute | CI flawfinder at level 4 |
| 2026-10-10 | 1 | cppcheck: four buffers filled by system services or RMS looked uninitialised to it | Informational | zero-initialised | CI cppcheck |
| 2026-10-10 | 1 | Phase 1 gate review: any local process could connect to the loopback FastCGI ports, bypass lighttpd and choose its own REMOTE_ADDR, guessing passwords without breakin evasion | High (local attacker) | gateway secret shared with lighttpd (this commit) | unit `test_gateway`, API suite, and on VMS a direct connection gets 403 |
| 2026-10-10 | 1 | Files created by the service took the account's default protection, including group read | Low (already behind a no-group directory) | pool sets `(S:RWED,O:RWED,G,W)` as the default | phase-exit listing |
| 2026-10-10 | 1 | API responses had no CSP of their own | Informational (hardening) | `default-src 'none'; frame-ancestors 'none'` on every API response | API suite |
| 2026-10-10 | 1 | Claimed "IMPERSONATE alone suffices" from a failed-sign-in test; the first successful sign-in failed: `$PERSONA_CREATE` needs GRPPRV/SYSPRV to read the user's UAF record | Process (false verification) | correction in PHASE1.md; D2 to be amended | checklist item: verify the success path as the real account |
| 2026-10-10 | 1 | Privilege masks above bit 31 truncated to 0 make `$SETPRV` a silent no-op that returns NORMAL (probe code) | Recorded as a rule | PHASE1.md | checklist item |
| 2026-10-10 | 1 | Pool started with `RUN/DETACHED LOGINOUT` without `/AUTHORIZE`: the processes took the batch job's privileges, not the UAF's, so the authorized SYSPRV never reached them (fail-safe: persona creation failed) | Informational (deployment) | fe2aa18 | phase-exit check of `F$GETJPI(pid,"AUTHPRIV")` |
| 2026-10-10 | 1 | Phase exit: review of the SYSPRV bracket and the pool change; browser checks of sign-in, D9, sign-out, DISUSER and expired passwords | None | | PHASE1.md "Phase exit checks" |
