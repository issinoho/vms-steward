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
