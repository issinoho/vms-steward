# Phase 7: logical names

Read-only first, then define and deassign, as for users and identifiers.

## How names are read (probes, 2026-10-11)

There is no system service that lists a table (STARLET exports none). So D14:
- **Listing a table:** a short-lived detached process, created under the viewer's
  persona, runs the fixed procedure `STEWARD_LNM.COM`. It takes a table and a
  pattern as data from one mailbox, and `SHOW LOGICAL/FULL` writes to another.
- **One name:** `$TRNLNM`, in-process, under the persona.

`probes/probe_lnm.c`, as STEWARD_TEST (no privileges), with the procedure in
`STEWARD$ROOT:[COM]` (removed afterwards):

| Table, pattern | Names | Time | Note |
|---|---|---|---|
| LNM$SYSTEM_TABLE, `SYS$S*` | 12 | 0.30s | |
| LNM$SYSTEM_TABLE, `*` | 341 | 5.2s | the probe polled every 10 ms per line; the service will block on the read |
| LNM$GROUP, `*` | 0 | 0.12s | resolves to LNM$GROUP_000362, STEWARD_TEST's own group |
| LNM$SYSTEM_DIRECTORY, `*` | 85 | 1.4s | every shareable table, with protection and owner |
| `LNM$SYSTEM_TABLE/OUTPUT=X`, `*` | none | 0.12s | refused by the procedure's own check |

The process ran as STEWARD_TEST, with its UIC and its privileges only (accounting).
What it could not see, it did not show.

## Scope

**Read-only (7a):**
- `GET api/v1/logicals/tables`: the shareable tables (the system directory), with
  protection, owner and attributes. The viewer's group table is shown as theirs.
  Process and job tables are left out: under a persona they would be the service
  process's own, not the viewer's.
- `GET api/v1/logicals?table=&filter=`: the names in a table, each with its access
  mode, attributes and equivalences (with their own attributes), parsed from
  `SHOW LOGICAL/FULL`.
- `GET api/v1/logicals/{table}/{name}`: one name, by `$TRNLNM` (every index), and what
  each equivalence translates to in turn, as `SHOW LOGICAL` does.
- The view: tables on one side, names with a DCL-style filter, and a name's
  translation chain.

**Changes (7b, after 7a's exit):** define (table, mode, attributes, one or more
equivalences) and deassign, by `$CRELNM` and `$DELLNM` under the persona. OpenVMS
decides: SYSNAM for the system table in executive mode, GRPNAM or the table's
protection for others. Each change goes in the audit log, needs CSRF, and the browser
asks first.

## Exit (7a)

- The tables and names match `SHOW LOGICAL/FULL` and `SHOW LOGICAL/STRUCTURE`, for a
  privileged viewer and for STEWARD_TEST.
- A name a viewer may not read is not shown.
- Hostile tables and patterns are refused by both Steward and the procedure.
- No helper process is left behind, on timeout or error.

## Where this stands (2026-10-11, end of session): resume here

**Built (7a, read-only), not yet released or installed by kit:**
- **Core:** `src/core/st_lnm.{h,c}`: the input checks, which refuse process and job
  tables and search lists through them, and the SHOW LOGICAL/FULL parser. It is unit
  tested and fuzzed; the fuzzer gives each line a buffer of exactly its length, and
  caught an overread that has since been fixed.
- **Platform:**
  - `st_plat_lnm_list`, the D14 helper process. It sends table, pattern and the
    session's enabled privileges as data, and waits on a blocking read with a 30 s
    timer, deleting the helper on timeout.
  - `st_plat_lnm_get`, in-process `$TRNLNM`, only in a real table of
    LNM$SYSTEM_DIRECTORY.
  - The stub, with sample tables.
- **API:** `GET api/v1/logicals/tables`, `GET api/v1/logicals?table=&filter=` and
  `GET api/v1/logicals/{table}/{name}`, with a translation chain through the viewer's
  group, system and cluster tables.
- **View:** `www/js/logicals.js`: tables grouped down the side, a DCL filter line, the
  table header, names, and the chain on click.
- **Kit:** `vms/steward_lnm.com` and `LOGICALS.JS` are in the kit, and the
  `kit-has-files` audit rule checks them.
- **Tests:** 250 unit checks pass. `tests/vms/phase7_live.py` on x86 gives 16 ok,
  0 failed (2026-10-13).

Found on the node and handled:
- `$STATUS` is a string: the procedure uses `F$INTEGER`.
- RMS puts end-of-file messages in the mailbox: they are skipped.
- SHOW LOGICAL answers IVLOGTAB, at *warning* severity (%X158), both for a table that
  does not exist and for one not readable. Steward compares without the severity and
  gives a 404.
- The helper is a fresh login, with only the account's defaults. The session's D9
  privileges are passed to it, and it runs `SET PROCESS/PRIVILEGE`.
- Timing on x86: the whole system table in 0.50s, one name 0.31s, the tables list
  0.37s.

**Next, in order:**
1. ~~**The one failing live check.**~~ Done 2026-10-13: `st_plat_lnm_get` on VMS
   refuses LNM$SYSTEM_DIRECTORY as the stub did (DECISIONS D14). Live: 16 ok, 0 failed.
2. **Docs:** api.md (the three endpoints), security.md (Phase 7: the helper process,
   data-only mailboxes, the process-table refusal, the D9 privileges, IVLOGTAB), and
   the PHASE7 exit record.
3. **Release:** `make audit`, then commit. Build the kit (bump to 0.5.0, T0.5-0),
   install it on x86, and remove the hand-copied `STEWARD$ROOT:[COM]STEWARD_LNM.COM;*`
   versions first, or purge after the kit puts its own there.
4. **Exit:** ask the user for the 7a browser exit checks, then commit, push and release
   per the standing pattern. 7b (define, deassign) comes after.

Also open from earlier: 0.4.1, the Phase 5 review fixes, was never released on its
own. It will go out with 0.5.0 unless the user wants it sooner.
