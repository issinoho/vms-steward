# Phase 4: create, copy and delete users

## Approved scope and test data (user, 2026-10-11)

- **Test accounts, created and removed:** STEWARD_NEW and STEWARD_COPY, in the test group
  [362,*] (UICs [362,10] and [362,11]). The test identifier is STEWARD_TEST_ID, as in
  Phase 3.
- **Home directory:** creating one is optional, a checkbox off by default. AUTHORIZE
  never creates directories, so the default matches it. When ticked, Steward creates
  the directory under the caller's persona, owned by the new account.

## Probes (2026-10-11, x86 node): `probe_uafcreate`, and AUTHORIZE itself as the reference

`probe_uafcreate` uses UAFDEF's own `struct _uaf` (`SYS$LIBRARY:SYS$LIB_C.TLB`, compiled
with `+SYS$LIBRARY:SYS$LIB_C/LIBRARY`). The compiler then gives exactly the system's
layout (`#pragma __nomember_alignment`); no offsets are written by hand.
`sizeof(UAF)` = `UAF$C_LENGTH` = 1412; the fixed part is 644.

**Create (from DEFAULT):**
- The probe reads the template record by key (shared, no lock), copies it and changes
  the username (keeping the template's tag byte), UIC and owner. It clears the
  password hashes, salt, password dates, login times and failure count, then
  `$PUT`s the record.
- `$PUT` returned `%RMS-S-OK_DUP`, a success: an alternate key is shared.
- Then a random password, pre-expired, with `$SETUAI` (the system hashes it), and the
  UIC identifier with `$ADD_IDENT`.
- DEFAULT's record is 644 bytes long, with `usrdatoff` 0 and tag `%X20`.
- **AUTHORIZE ADD STEWARD_COPY** gave the same result: DEFAULT's values, *including
  DisUser*, a pre-expired password, and the UIC identifier added
  (`%UAF-I-RDBADDMSGU`). A new account from DEFAULT is therefore disabled until
  someone clears DISUSER, as with AUTHORIZE. Steward offers that in its create dialog.

**Copy:** `AUTHORIZE COPY STEWARD_TEST STEWARD_COPY` kept every field of the source,
including its owner and its *default directory* (`[STEWARD_TEST]`). It pre-expired the
password and added the UIC identifier. It did **not** copy the source's held
identifiers: STEWARD_TEST held STEWARD_TEST_ID, and STEWARD_COPY did not. Steward
offers that as an option, off by default to match.

**Remove:** with STEWARD_TEST_ID granted to both test accounts:
- `AUTHORIZE REMOVE STEWARD_COPY` removed the record, the UIC identifier
  (`%UAF-I-RDBREMMSGU`) and the user's holding of STEWARD_TEST_ID.
- The probe's REMOVE did the same for STEWARD_NEW: `$FIND_HELD` + `$REM_HOLDER` for
  every holding, `$REM_IDENT` for the UIC identifier, then RMS `$FIND` + `$DELETE`
  of the record. Afterwards AUTHORIZE knew neither the user (`BADSPC`) nor the
  identifier (`NOSUCHID`), and STEWARD_TEST_ID had no holders.

After the probes the node was as before: no STEWARD_NEW, STEWARD_COPY or
STEWARD_TEST_ID, and STEWARD_TEST holding nothing.

## Built, and checked on the node (2026-10-11): `tests/vms/phase4_live.py`

The checks run through the real dispatcher and platform as STEWARD_ADM's persona with
SYSPRV switched on, each confirmed with AUTHORIZE. 23 of 23 passed:
- **Refusals:** OpenVMS refused STEWARD_TEST and STEWARD_ADM without SYSPRV.
- **Undo:** a password OpenVMS refused (`PWDSYNTAX`, after the `$PUT`) failed the
  create and left neither record nor identifier.
- **Create from DEFAULT:**
  - owner, UIC, DISUSER cleared as asked, default directory, pre-expired password;
  - quotas and password policy as DEFAULT's;
  - the UIC identifier;
  - a home directory owned by the new user.
- **Copy of STEWARD_TEST:** the source's fields, its directory included (as AUTHORIZE
  COPY). An existing username was refused.
- **Delete of both:** AUTHORIZE afterwards knew neither the users nor their
  identifiers.

**Found on the way:** a home directory requested for an account with no default
device was created on the serving process's disk. Steward now refuses, with a warning,
and the dialog prefills a device (security.md audit record).

## Phase exit checks (2026-10-11, x86 node, installed kit 0.3.0, through nginx proxy manager)

The user signed in as STEWARD_ADM with SYSPRV switched on, and did each check in the
browser:

| Check | Evidence |
|---|---|
| New user from DEFAULT, DISUSER cleared, not pre-expired | `user-create target="STEWARD_NEW" ... detail="default_device; default_directory; flags-DISUSER; from DEFAULT, [200,2]"` |
| Copy of STEWARD_TEST, with "copy identifiers" | `user-copy target="STEWARD_COPY" ... from STEWARD_TEST, [362,4], identifiers copied` (STEWARD_TEST held none) |
| Delete both | `user-delete ... ok`; AUTHORIZE: no such users, no such identifiers |
| (incidentally) the minimum-length check at a password change | `password-change ... refused ... must be at least 15 characters`, then `ok` |

The user did not sign in as the new account, so that was shown separately with
`api_probe`, through the real sign-in path: an account created by Steward (STEWARD_NEW,
[362,10], password set, not pre-expired) signed in through `SYS$ACM` (201), a wrong
password was refused (401), and the account was deleted (AUTHORIZE: `BADSPC`).

**One change from the checks:** the new-user dialog had suggested DEFAULT's own UIC
group, which on the x86 node is a real user's group: STEWARD_NEW landed in [200,2].
The dialog now leaves the group empty for a new user (as AUTHORIZE ADD makes you
choose a UIC) and suggests a member only once a group is entered. A copy still starts
in the source's group.
