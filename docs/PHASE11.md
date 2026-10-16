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
