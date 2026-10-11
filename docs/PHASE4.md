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
