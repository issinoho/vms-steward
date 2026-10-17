# Phase 14: error log

**Status: 14a closed (2026-10-17)** on the user's browser checks of 0.14.0. The user
approved D23 and the suggested answers below ("Agreed").
**14b: changes, being built (2026-10-17)**: the user approved D24, D25 and the suggested
answers ("Agreed").

What OpenVMS records about the hardware and the system itself: the error log
(`ERRLOG.SYS`, written by ERRFMT), the crash history (CLUE's summary of each crash
dump) and each device's error count. Read-only first (14a), as for the earlier areas.

## What the probes found (NOTES.md)

`probes/probe_errlog.com` and follow-up commands on x86, as the work account with
privileges off and then with SYSPRV.

| Source | Who may read it | Notes |
|---|---|---|
| `SYS$ERRORLOG:ERRLOG.SYS` (`SYS$SYSROOT:[SYSERR]`, 1,437 blocks) | (S:RWED,O:RWED,G:RE,W:), owner [SYSTEM]: SYSPRV, or the SYSTEM group | 1,807 events since 20-APR-2023: 255 time stamps, 860 volume mounts, 200 dismounts, 242 system service messages, 171 system bugchecks, 78 crash restarts. Without access an open reports **file not found**, not PRV (the search list masks it) |
| `ANALYZE/ERROR_LOG` (classic, `ERF.EXE`) | — | not on x86: image not found |
| `ANALYZE/ERROR_LOG/ELV TRANSLATE` | as the file | the decoder that ships. `/ONE_LINE`: one line an event (number, type, time, node, class), 4 s for the whole file; `/ENTRY=(START:n,END:n)`: one event in full, field by field (description, bit range, value, translation), 5 s (it scans); `/SUMMARY`: counts by class and the first and last; also `/SINCE`, `/BEFORE`, `/INCLUDE`, `/EXCLUDE`. Without access it prints `%ELV-E-FILOPNERR ... RMS-E-FNF` and **exits with success** |
| CLUE crash listings, `SYS$COMMON:[SYSERR]CLUE$<node>_<ddmmyy>_<hhmm>.LIS` | (S:RWED,O:RWED,G:RE,W:): SYSPRV; an open without it reports PRV | 37 on x86 (Aug 2023 to Oct 2026), about 47 blocks each. Page 1 is a "Crashdump Summary": crash time, bugcheck type and text (e.g. `PGFIPLHI, Pagefault with IPL too high`), current process and image, failing PC and module, boot time and uptime, then registers and stacks |
| `$GETDVI DVI$_ERRCNT`, each device | anyone | all 0 on x86 (`SHOW ERROR`: no device errors) |
| `SYS$MANAGER:OPERATOR.LOG` (OPCOM's log) | SYSPRV: even its directory entries are refused | 9 versions kept |

## Design (D23, proposed)

- **The error log through the D14 helper**, as the viewer, a fifth fixed procedure
  `STEWARD_ERRLOG.COM`: ELV TRANSLATE `/ONE_LINE` (with `/SINCE` and `/BEFORE` for the
  range asked) for the list, `/ENTRY=(START:n,END:n)` for one event in full, and
  `/SUMMARY` for the counts. Its output is parsed in core. ERRLOG.SYS's format is not
  documented, and ELV is the decoder OpenVMS ships, so Steward does not parse the
  binary. A viewer without access gets OpenVMS's refusal, with the explanation that
  ELV calls it "file not found" (as for accounting, NOTES.md); ELV's success status is
  not trusted, its messages are.
- **Crash history in-process**, under the persona (as D20 reads VMSINSTAL's history):
  the CLUE listings in `SYS$ERRORLOG`, newest first, each with page 1's summary
  parsed in core (time, bugcheck, process, image, module, PC, uptime), and the whole
  listing shown on request as text. The crash restarts in the error log point to them.
- **Device error counts** in-process, `$GETDVI DVI$_ERRCNT` for each device: open to
  anyone, shown at the top, the ones with errors first.
- **`GET api/v1/errorlog?since=&before=&class=`**, **`GET api/v1/errorlog/{n}`**,
  **`GET api/v1/crashes`**, **`GET api/v1/crashes/{name}`**, **`GET api/v1/devices/errors`**.
- **The page**, "Error log": the device counts, the events (newest first; filter by
  class; each opens its translation), and the crashes (each opens its summary and
  listing).

Alternatives considered:
- **Parsing ERRLOG.SYS in-process**: no process per request, but the record formats
  (EMB headers and a body per device type) are not documented for x86, and ELV's
  translations (bit fields, names) would have to be rebuilt.
- **ELV run by the service**: its view and its privileges, not the viewer's (D2).
- **Running CLUE (`ANALYZE/CRASH_DUMP`) on the dump**: needs the dump and CMKRNL;
  the listings CLUE already writes at boot hold the summary.

## Questions for the user

1. **Scope.** The error log, the crash history (CLUE) and the device error counts,
   as above. And OPCOM's `OPERATOR.LOG` too (the newest version, read in-process,
   newest lines first), or leave it for later?
2. **Default range** for the event list: the last 30 days, with 7 days, a year and
   everything to choose? (Everything is 1,807 events here, 4 s.)
3. **Access.** The error log, the crash listings and OPERATOR.LOG need SYSPRV (or the
   SYSTEM group) as OpenVMS sets them; viewers without it see the refusal. STEWARD_ADM
   with SYSPRV switched on is the test viewer. Agreed?
4. **14b** (changes: starting a new error log file, purging old crash listings,
   starting a new OPERATOR.LOG): decided after 14a?

Suggested answers: 1 include OPERATOR.LOG; 2 yes; 3 yes; 4 yes, later.

Answers (2026-10-17, "Agreed"): the suggestions, all four.

## Exit (14a)

- On x86, through `api_probe`: the event list and an event against ELV run by the
  work account; the crashes against the listings; STEWARD_TEST refused, STEWARD_ADM
  with SYSPRV served, without it refused (D9).
- Core parsers unit-tested on captured ELV and CLUE output (with node details
  replaced); a UI test on the stub; a kit and the user's browser checks.

## Built (14a)

- `STEWARD_ERRLOG.COM`, the fifth D14 procedure: ELV TRANSLATE `/ONE_LINE` (with
  `/SINCE=-<days>-`) or `/ENTRY`, given the reply mailbox with `/OUTPUT=` (ELV ignores
  a SYS$OUTPUT defined for it, NOTES.md). Parsed in core (`st_errlog.c`), by the
  underscored headings' columns; a refusal told by ELV's message.
- CLUE's listings, OPERATOR.LOG and the device counts in-process as the viewer.
  OPERATOR.LOG, like ERRLOG.SYS, says "not found" to a viewer without access (the
  `SYS$SYSROOT` search list); both are reported as refusals, with why.
- `GET api/v1/errorlog`, `errorlog/{n}`, `crashes`, `crashes/{name}`, `operator-log`,
  `device-errors` (api.md); the page "Error log".

Live test: `tests/vms/phase14_live.py x86` 19 ok, 0 failed. Against ELV run by the
work account: the same 160 events of the last 30 days in order, 1,807 for the whole
file; event 1801 (the latest crash restart) field by field, bit fields indented; 404
for an event not there. The 37 CLUE listings, the newest's bugcheck as in its file,
its whole listing. OPERATOR.LOG;243, newest message first, as the file ends.
Device errors: none of 556, as `F$GETDVI ERRCNT` says. STEWARD_TEST refused all three
protected sources; STEWARD_ADM refused without SYSPRV switched on (D9), served with it.
Linux: 490 unit checks (the parsers on lines captured from x86, node renamed, and the
endpoints on the stub), the UI tests (14 for this page) and `make audit`. x86: 490
native checks, no compiler messages.

Kit T0.14-0 (0.14.0), built by `tools/kit.sh x86` (490 native checks), SHA-256
`41f7d447d83ef00477a3da002b32068d552fa29f81ee538d8a5ce739132c87b0`, for the browser
checks. After it is installed, `PHASE14_HELPER=installed python3
tests/vms/phase14_live.py` runs the installed procedure.

Installed (2026-10-17): the user installed 0.14.0 on x86 and restarted the pool (the
pool and recorder logs show 0.14.0 starting cleanly). `PHASE14_HELPER=installed
tests/vms/phase14_live.py x86`, with STEWARD$ROOT:[COM]STEWARD_ERRLOG.COM: 19 ok, 0
failed.

Browser checks: confirmed by the user (2026-10-17). 14a closed.

## 14b: changes (D24, proposed)

The maintenance a system manager does on these files by hand, each under the viewer's
persona, so OpenVMS decides (D2), each audited, each confirmed in the page first.

### What the probes found (read-only, x86)

- **ERRLOG.SYS is not held open.** `SHOW DEVICE/FILES` lists OPCOM with
  `OPERATOR.LOG;243` open, nothing with ERRLOG.SYS: ERRFMT opens it for each batch of
  records, so a renamed file is simply not found at the next write and ERRFMT creates a
  new one (as the documentation's "start a new error log" says: rename or delete it).
- **A new OPERATOR.LOG**: `REPLY/LOG` needs OPER *and* a terminal enabled as an
  operator terminal, which a detached helper has not. Underneath, OPCDEF has the
  request: `$SNDOPR` with `OPC$_RQ_LOGI` (2) and `OPC$K_INITLOG` ("if one is open,
  close logfile; open new logfile"). Whether OPCOM accepts it from a process with OPER
  but no operator terminal is not known without sending it, which starts a new
  OPERATOR.LOG on the node: **a probe that needs the user's go-ahead** (question 3).
- The CLUE listings are plain files; CLUE$HISTORY.DAT and CLUE$COLLECT.DAT beside
  them are CLUE's own and are left alone.
- `[.RUN.LOGS]` holds 46 versions of the pool's `.COM` files and 46 of its `.LOG`
  files: each START writes new ones and nothing purges them (D25, below).

### Design

- **Start a new error log**: rename `SYS$ERRORLOG:ERRLOG.SYS` to
  `ERRLOG_<yyyymmdd>_<hhmm>.SYS` in the same directory, in-process under the persona
  (`$RENAME`: SYSPRV, as the directory and file are protected). ERRFMT starts a new
  ERRLOG.SYS at its next record. The old file is kept; the page can then read an
  older file with ELV (`GET api/v1/errorlog?file=`, the names `ERRLOG*.SYS` in
  SYS$ERRORLOG only).
- **Delete crash listings**: chosen ones, or all older than a date, in-process under
  the persona (`$ERASE`, SYSPRV). Only names `st_valid_clue_name` accepts.
- **Start a new OPERATOR.LOG**: `$SNDOPR` `OPC$_RQ_LOGI`/`OPC$K_INITLOG` in-process
  under the persona (OPER), if the probe shows OPCOM accepts it; otherwise left out
  (the page says to use `REPLY/LOG` at an operator terminal).
- **API**: `POST api/v1/errorlog/new`, `DELETE api/v1/crashes/{name}`,
  `POST api/v1/crashes/purge` (`{"before": "2026-01-01"}`), `POST
  api/v1/operator-log/new`; CSRF and same-origin as every change; each in the audit
  log with its outcome.
- **Tests**: renaming the real error log and deleting real listings are system
  changes, so the live test works on copies: a test hook (for `api_probe` only, as
  the helper paths) points SYS$ERRORLOG's role at a scratch directory in the work
  directory holding a copy of ERRLOG.SYS and of some listings. The real files change
  only when the user tries it in the browser.

Alternatives considered:
- **Deleting ERRLOG.SYS** rather than renaming: simpler, but the history is lost; a
  renamed file can still be read and deleted later by hand.
- **REPLY/LOG through the D14 helper**: refused without an operator terminal.
- **A fixed number of crash listings kept** (purge to N): the dates are what a
  manager decides by.

### The OPCOM probe (2026-10-17, with the user's go-ahead)

`probes/probe_sndopr.c`, once, with OPER only: `$SNDOPR` accepted OPC$_RQ_LOGI, but
OPCOM neither replied nor started a new log (OPERATOR.LOG still ;243, nothing written
to it). So, as planned, starting a new OPERATOR.LOG is left out of 14b; the page says
to use `REPLY/LOG` at an operator terminal. OPCDEF's newer `OPC$_X_LOGFILE` form was
not tried (a second probe would need the user's go-ahead).

## Pool logs (D25)

`STEWARD_POOL.COM START` purges `[.RUN.LOGS]` to the newest **10** versions of each
process's `.COM` and `.LOG` (`PURGE/KEEP=10`), before it writes new ones; a setting,
`STEWARD_LOG_KEEP` (1 to 100), changes the number. The service account owns them, so
no privilege is needed. Tested in the work directory's own test pool.

## Questions for the user (14b and the pool logs)

1. **Error log**: rename to keep the old file (and let the page read older files), or
   delete it?
2. **Crash listings**: delete chosen ones and "older than a date", as above?
3. **OPERATOR.LOG**: may I send one `$SNDOPR` LOGI from the work account (OPER) as a
   probe? It starts OPERATOR.LOG;244 on x86, as `REPLY/LOG` would.
4. **Pool logs**: keep 10 of each, with `STEWARD_LOG_KEEP` to change it?

Suggested answers: 1 rename; 2 yes; 3 yes; 4 yes.

Answers (2026-10-17, "Agreed"): the suggestions, all four.

## Built (14b and D25)

- `POST api/v1/errorlog/new` (rename to `ERRLOG_<yyyymmdd>_<hhmm>.SYS`),
  `GET api/v1/errorlog/files` and `?file=` on the list and event, `DELETE
  api/v1/crashes/{name}`, `POST api/v1/crashes/purge`: in-process under the persona,
  audited. STEWARD_ERRLOG.COM takes the file as a fourth message (Steward fixes the
  directory, checks the name; the procedure checks its characters again).
- A viewer with SYSPRV switched on who finds no ERRLOG.SYS (after a new log, until
  ERRFMT's next record) is told that; anyone else is told that "not found" is also
  OpenVMS's answer to a viewer without access.
- The page: a file choice (current or renamed), "Start a new error log" (type
  ERRLOG.SYS to confirm), crash listings chosen or "older than a day" deleted (type
  DELETE to confirm); a pointer to `REPLY/LOG` for the operator log.
- `STEWARD_POOL.COM START` purges `[.LOGS]` to `STEWARD_LOG_KEEP` (10) versions of
  each `.COM` and `.LOG`.

Live test: `tests/vms/phase14b_live.py x86` 15 ok, 0 failed, on copies in the work
directory (`API_PROBE_ERRLOG_DIR`): ERRLOG.SYS renamed ERRLOG_20261017_1219.SYS,
read back by name (the same 1,807 events), 404 with why until a new one exists, 404
for a second new log; STEWARD_TEST refused both changes, STEWARD_ADM refused without
SYSPRV switched on; a listing deleted, the other two purged before a day; every change
and refusal in the audit log; a test pool's START purged 15 versions of each to 5;
the system's SYS$ERRORLOG unchanged (ERRLOG.SYS and 37 listings). Linux: 509 unit
checks, 56 API checks, the UI tests (the new controls included), `make audit`.

Regression: `tests/vms/phase14_live.py x86` with the edited helper (the file as a
fourth message): 19 ok, 0 failed.

Kit T0.15-0 (0.15.0), built by `tools/kit.sh x86` (509 native checks), SHA-256
`aab2e0f65e840471ff32a4c94c669ce2cb0554c9ef5cd72af45dee3ec35e6ef7`, for the browser
checks. Its RESTART uses the new pool procedure, so the first START with it purges
`[.RUN.LOGS]` to 10 of each.
