# Brief for an external security review and penetration test

Steward is a browser console for OpenVMS. It can change who may sign in to a system
and with what privileges, so a flaw in it can be a privilege escalation in the
operating system. This brief is for an independent reviewer and penetration tester
(Phase 5, D8). It says what to look at, what is already known, and how to set up a
test system. The threat model, invariants and the audit record are in
[`security.md`](security.md); the API is in [`api.md`](api.md).

## What it is

- `STEWARD.EXE`: a C99 FastCGI responder (no libraries beyond VSI SSL3's libcrypto),
  run as a pool of detached processes under a service account, `STEWARD`. That
  account holds **IMPERSONATE**, TMPMBX and NETMBX. SYSPRV is authorized but kept
  off, except around `$PERSONA_CREATE`.
- It is served by lighttpd for OpenVMS on a port of its own (8443 by default), usually
  behind a TLS proxy (nginx proxy manager here).
- **Authorization is OpenVMS's (D2).** Sign-in goes through `SYS$ACM`. Each request then
  runs under a persona of the signed-in user, so the operating system decides what the
  request may read or change. Steward has no permission model of its own; any place
  where it decides access itself is a finding.
- A plain-JavaScript front end (no build step, no third-party code), with a strict CSP.

## In scope, in order of concern

1. **Becoming someone else.** Anything that makes a request run as a different user
   than the session's, or with a privilege the user is not authorized for. That
   includes a persona left active after a request (the dispatcher ends it on every
   path, and the service exits if one leaks) and SYSPRV left on in the service.
2. **Sessions.** Token generation (256-bit, `RAND_bytes`), storage (only the SHA-256 of
   the token, in an RMS indexed file), idle and absolute expiry, sign-out, cookie
   attributes, CSRF (a per-session token plus Origin and Sec-Fetch-Site checks).
3. **Sign-in.** Usernames are validated before `$ACM`. Failures must not reveal which
   accounts exist. Break-in detection must see the real client address, not the
   proxy's (`X-Forwarded-For` is believed only from `STEWARD_TRUSTED_PROXIES`).
4. **Bypassing lighttpd.** The pool listens on 127.0.0.1 and requires a gateway secret
   that lighttpd adds. A local user who reaches the port directly must be refused,
   or they could choose their own `REMOTE_ADDR` and evade break-in detection.
5. **Parsing.** FastCGI records, HTTP parameters, JSON bodies, query strings. Phase 6
   adds the binary parsing of accounting records, security audit journal records,
   OpenSSH logs and Steward's own audit log (`st_plat_vms.c`, "access history"). Those
   files are written by the system, but a user who can cause a login failure chooses
   the username recorded.
6. **Writing SYSUAF directly** (Phase 4, D6). User creation `$PUT`s a SYSUAF record
   built from a template's record, under the persona. Look at the rollback on failure
   and at what a crafted template could do.
7. **The browser side.** Every string from OpenVMS reaches the page as a text node
   (`dom.js` has no HTML helper). There is a CSP with `default-src 'self'`, no inline
   script or style, and `frame-ancestors 'none'`.

## Out of scope

- OpenVMS itself, VSI TCP/IP Services, VSI SSL3 and lighttpd, except where Steward
  misuses them.
- Denial of service by an account that already holds SYSPRV or READALL. For example, a
  very large accounting file makes access history slow for whoever asks for it.

## Known and accepted

- **Access history reads whole files per request.** It shows failed usernames, which
  are sometimes a password typed into the wrong box. Only viewers OpenVMS lets read
  those files (SYSPRV or READALL) see them; docs/security.md, Phase 6.
- **Behind a proxy, the client address is the proxy's** unless `STEWARD_TRUSTED_PROXIES`
  is set (README.VMS).
- **No rate limit of Steward's own.** OpenVMS break-in evasion applies to sign-in
  (that is the point of passing the real address), and nothing else is reachable
  without a session.

## Setting up a test system

1. OpenVMS x86-64 V9.2-x with VSI TCP/IP Services, VSI SSL3 and
   [vms-lighttpd](https://github.com/issinoho/vms-lighttpd) 1.4.85-vms2.
2. Install the kit from the [releases page](https://github.com/issinoho/vms-steward/releases),
   and follow `[STEWARD.DOC]README.VMS`: `STEWARD$CONFIGURE`, include the lighttpd
   fragment, `STEWARD$CONTROL START`.
3. Test accounts:
   - one with no privileges;
   - one with SYSPRV authorized but not default, as an administrator would have;
   - one DISUSERed;
   - one with an expired password.
   Use a system whose SYSUAF you can afford to lose. Back it up first.
4. For a white-box review, the source is at
   [github.com/issinoho/vms-steward](https://github.com/issinoho/vms-steward). The Linux
   build (`make dev`) runs the whole service on an in-memory stand-in for OpenVMS,
   which is convenient for fuzzing and for testing the browser side.

## What we would like back

For each finding: what it is, how to reproduce it, its severity, and the commit it
was found at. Findings go into the audit record in `security.md`, each with its fix
commit and a regression test that fails without the fix.
