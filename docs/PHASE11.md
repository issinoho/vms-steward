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
`(RWED,RWED,RE,)`: so also readable by UIC group 1. Every command takes `/OUTPUT=`
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
