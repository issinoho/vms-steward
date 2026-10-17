# Phase 14: error log

**Status: 14a being built (2026-10-17).** The user approved D23 and the suggested
answers below ("Agreed").

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
failed. Awaiting the user's browser checks.
