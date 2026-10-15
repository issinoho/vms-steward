# Phase 10: system parameters

Read-only (the user's choice, 2026-10-15): changing parameters is decided later, once
this is in use. Design: DECISIONS D18.

## How parameters are read (probe, 2026-10-15)

A batch job as STEWARD_TEST (TMPMBX, NETMBX only) ran `F$GETSYI` and `MCR SYSGEN` with
`SHOW MAXPROCESSCNT`, `SHOW MAXSYSGROUP` and `SHOW/DYNAMIC`: SYSGEN ran for it and
printed each parameter's current value, default, minimum, maximum, unit and dynamic
flag. `$GETSYI` gives current values only. OpenVMS has no service that gives the rest,
so, the user chose, SYSGEN SHOW/ALL runs in the D14 helper process, which is the
viewer, and Steward parses its fixed columns (NOTES.md).

## Built (2026-10-15)

- **Core:** `src/core/st_sysgen.{h,c}`, the SHOW/ALL parser: the name to its first
  blank, values by column (the current ends in 33, or 34 when quoted), the unit, the
  dynamic flag, quoted strings, "internal value" lines. Unit tested; fuzzed.
- **Helper:** `st_plat_lnm_list`'s machinery is now `helper_run`, shared: the fixed
  procedure, data-only mailboxes, the deadline, the termination mailbox, the deleted
  helper. `vms/steward_sysgen.com` reads only the privileges, checks them, and has
  SYSGEN `SET/OUTPUT=` the reply mailbox through a user-mode logical name (SYSGEN's
  commands are data lines, which DCL does not substitute into). Its path is resolved
  at start-up to a physical one, as the logical-names procedure's is.
- **API:** `GET api/v1/sysgen?filter=`. **View:** `www/js/sysgen.js`.
- **Tests:** 375 unit; `make ui-test` 28; on x86 `tests/vms/phase10_live.py` 7 ok, 0
  failed: as STEWARD_TEST, the same 317 parameters as SYSGEN SHOW/ALL run by the work
  account, no current value differing; SCSNODE as a string; GBLPAGES dynamic with its
  internal value; the filter; no helper left.

## Exit

- The parameters match SYSGEN SHOW/ALL, for STEWARD_TEST.
- The logical-names listing still passes `phase7_live.py` through the shared helper.
- Browser checks (the user's); the security gate.
