# Alpha port: status

Started 2026-11-14. The node: AXPBOX, an AlphaServer DS10L (Charon-AXP), OpenVMS
V8.4-2L2, VSI C V7.4-002, VSI SSL3, TCP/IP V6.0-31. `tools/nodes.conf` entry `alpha`.
Findings, each with how it was observed, are in NOTES.md (2026-11-14 entries).

## Verified

- **Probes:** all sixteen of `probes/run_probes.com` build; `probe_rmi` run unprivileged:
  `RMI$_FRLIST` and `RMI$_MODLIST` take only a longword (NOTES.md).
- **Build:** the same sources, with two Alpha changes: the `$GETRMI` longword retry, and
  `/FLOAT=IEEE_FLOAT` (Alpha's C defaults to G_FLOAT). `build_vms CLEAN`, then `build_vms
  TEST`: `BUILD-OK`, no warnings, `528 checks, 0 failed`, `TEST-OK`.
- **Live, read-only, as IAIN through `api_probe`:** `/api/v1/system` (node AXPBOX, arch
  Alpha, AlphaServer DS10L, memory free = SHOW MEMORY) and `/api/v1/monitor` twice 10 s
  apart (free memory right, CPU modes 100 ticks a second).

- **Test accounts** (the user's approval, 2026-11-14): `tests/vms/test_accounts.com` made
  STEWARD_TEST [362,1] and STEWARD_ADM [362,3] (group 362 was free); STEWARD_ADM was then
  authorized SYSLCK for phase 12, as on IA64. The phase 7 helper is a copy of
  `vms/steward_lnm.com` in `SYS$SYSDEVICE:[STEWARD_TEST]` (`PHASE7_HELPER`).
- **Phase live tests through `api_probe`:** 3 (23 ok), 6 (11), 7 (20), 7b (24), 8b (see
  the note below), 9 (9), 9b (13), 10 (7), 11 (9, after the charge fix), 12 (8), 12b `--find-only`
  (6), 13 (14), 13b (19), 14 (19), 14b (16).

Phase 8b, three runs: every check of what Steward does passed in one run or another, the
refusals (409 for a system process and for its own image) included. What failed in the
last run (10 ok, 2 failed) is the test's own follow-up, `exists()`, reading a process
through interactive DCL, whose output the Alpha sometimes loses (`vms.sh: ... did not
start`), and a 60 s stand-in outliving the node's slow SSH calls less often than on x86.

## Differences found, and what changed

- `RMI$_FRLIST` and `RMI$_MODLIST` take only a longword: retried with 4 bytes.
- VSI C defaults to G_FLOAT: `/FLOAT=IEEE_FLOAT` in `build_vms.com` and `run_probes.com`.
  Without it `probe_hold`'s 20 s hold lasted 0.02 s, which is what phase 8b first tripped on.
- `SHOW LICENSE/CHARGE` lists types A to I (11 lines); the parser now keeps 16 lines and
  takes the first type with units (A, 15).
- Tests that assumed x86 or IA64: phase 14's architecture (4, Alpha), phase 14b's listing
  count (two on AXPBOX), and phase 12b's and `make_stwdemo.com`'s PCSI base (AXPVMS).

## Installed (2026-11-14, the user's approval)

- **lighttpd:** vms-lighttpd's AXPVMS kit (V1.4-85E3), `VMSLIGHTTPD$CONFIGURE LIGHTTPD [361,1]
  SYS$SYSDEVICE:[VMSLIGHTTPD_DATA] 80 YES NO` (no PHP); LIGHTTPD.EXE installed with OPER.
- **Steward:** kit T0.16-0 for AXPVMS (`tools/kit.sh alpha`, now batch jobs there: a clean
  build, 530 native checks, the kit), installed; `STEWARD$CONFIGURE STEWARD [362,2]
  SYS$SYSDEVICE:[STEWARD_DATA] 8443 LIGHTTPD "" YES`; its `include` added to LIGHTTPD.CONF.
  The pool (STEWARD_19300, _19301) and the recorder (STEWARD_R19300) run as STEWARD;
  `/api/v1/health` through lighttpd on 8443: `{"status":"ok"}`; the page 200; an unsigned
  `/api/v1/session` 401.
- **Phases 4 and 8**, which needed it installed: 23 ok and 10 ok. Every phase has now passed
  on the Alpha.
- **At boot:** `SYSTARTUP_VMS.COM;46` `st_13 = "lighttpd|SYS$STARTUP:VMSLIGHTTPD$STARTUP.COM"`,
  `st_14 = "Steward|SYS$STARTUP:STEWARD$STARTUP.COM"`; `SYSHUTDWN.COM;13` their shutdown
  procedures after vmsnotify's. Not yet seen through a real reboot.

## Not yet

- HTTPS for browsers: a reverse proxy in front of 8443 (as `ia64.issinoho.com` for IA64), or
  a certificate in lighttpd. No trusted proxy is configured yet.
- A real reboot.
