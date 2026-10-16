# Phase 11: licences

Read-only (11a) now; whether to offer changes is decided once it is in use (the user,
2026-10-16). Design: DECISIONS D19.

## How licences are read (probe, 2026-10-16)

OpenVMS has no documented service that lists licences. The License Management
Facility gives two views, and `probes/lic_view.com` (in batch, NOTES.md) shows who may
read each:

| Asking as | `SHOW LICENSE/FULL` (loaded, in memory) | `SHOW LICENSE/UNIT_REQUIREMENTS` | `LICENSE LIST/FULL` (LMF$LICENSE database) |
|---|---|---|---|
| STEWARD_TEST, none | 11 shown | shown | %RMS-F-PRV |
| my account, none on | | | %RMS-F-PRV |
| my account, SYSPRV only | | | 11 shown |
| my account, READALL only | | | 11 shown |

The database is `SYS$COMMON:[SYSEXE]LMF$LICENSE.LDB`, owner [1,1], protection
`(RWED,RWED,RE,)`: so also readable by the system category (a UIC up to MAXSYSGROUP)
and UIC group 1, and with BYPASS. Every command takes `/OUTPUT=`
by a logical name, as SYSGEN's `SET/OUTPUT=` did for the D14 helper.

## Scope (approved by the user, 2026-10-16)

**Read-only (11a):** one view, from the D14 helper as the viewer:
- the licences loaded on this node (`SHOW LICENSE/FULL`): product, producer, units,
  version, release and termination dates, availability or "per core", activity,
  options;
- this node's charge (`SHOW LICENSE/UNIT_REQUIREMENTS`): the hardware, cores, units
  required;
- the database (`LICENSE LIST/FULL`), when the viewer may read it: every PAK with its
  issuer, authorization, status (active, disabled, ...), revision, hardware ID and who
  last changed it. For others, OpenVMS's refusal is shown as it is (D10).

## Built (2026-10-16)

- **Core:** `src/core/st_license.{h,c}`, the parser: the procedure's `%%PART%%` and
  `%%STATUS%%` markers; SHOW LICENSE's product lines and tab-led fields ("Per Core
  License" a flag, other bare lines the options); LICENSE LIST's PAKs between rules,
  the label to the first colon, an indented line continuing the field above; the
  database header; the charge's type and units. A field without a name of its own is
  kept in `other`. Unit tested; fuzzed.
- **Helper:** `vms/steward_license.com`, a third fixed procedure through `helper_run`:
  only the privileges as data; each command `/OUTPUT=` the reply mailbox directly.
- **API:** `GET api/v1/licenses`. **View:** `www/js/licenses.js`.
- **Tests:** 389 unit (native on x86 too); `make audit` (56 API, 200,000 fuzz rounds,
  `-fanalyzer`, rules); `make ui-test` 35; on x86 `tests/vms/phase11_live.py` 9 ok, 0
  failed: as STEWARD_TEST the same 11 loaded licences, in order, and the same charge
  as SHOW LICENSE run by the work account, the database refused with %X0001829C;
  as STEWARD_ADM with SYSPRV the same 11 PAKs, authorizations and statuses as LICENSE
  LIST; with SYSPRV authorized but not on, refused; no helper left.

## Exit

- The listings match SHOW LICENSE and LICENSE LIST, for STEWARD_TEST and STEWARD_ADM.
- Browser checks (the user's); the security gate, with the review of Phase 10's shared
  helper refactor carried over.

Kit T0.10-0 (0.10.0), built by `tools/kit.sh x86` (389 native checks), SHA-256
`4efd7fa8f43007f1d4b919501446e025585116486e4b31457fdba93c3fd476c6`, for the browser
checks.

**On the installed kit (2026-10-16):** the user's browser checks pass.
`PHASE11_HELPER=installed tests/vms/phase11_live.py` against `STEWARD_LICENSE.COM;1`:
9 ok, 0 failed.

**Security gate (2026-10-16).** An independent review of this phase and of Phase 10's
`helper_run` refactor: no Medium findings; security.md's audit record has the rest.
Fixed: a helper the viewer's LOGIN.COM made answer `%%END%%` (or write into the
termination mailbox) and stay was never deleted. Now only OpenVMS's DELPROC for its
PID counts as gone, and it is deleted otherwise. Reproduced first on the old build
(`probes/lnm_fakeend.com`: 200, and STW... left running as STEWARD_TEST until it
logged out), then on the fixed one: `phase7_live.py` with `PHASE7_FAILDIR` 23 ok (the
fake end answered in 1 s and deleted), `phase10_live.py` 7 ok, `phase11_live.py` 9 ok,
389 native, `make audit` clean. Also: event flags freed on a failed `LIB$GET_EF`; the
licence view's privilege hint only for RMS-F-PRV; who may read LMF$LICENSE stated in
full (the system category, BYPASS).

Kit T0.10-1 (0.10.1), with the review fixes, built by `tools/kit.sh x86` (389 native
checks), SHA-256 `13617da8e47a790c5f441e35535692b0375b1e29a2e2cd55d438935411d84a15`.
