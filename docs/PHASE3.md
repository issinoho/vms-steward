# Phase 3: users and rights, modify

## Approved scope and test data (user, 2026-10-10)

- **The user modified:** STEWARD_TEST. **The identifier created and deleted:**
  STEWARD_TEST_ID. Nothing else on the node is changed.
- **A privileged sign-in for the exit checks:** a dedicated test account,
  STEWARD_ADM, with SYSPRV authorized but not default (D9). The user creates it.
- **Self-service password change** is in scope. It also gives the expired-password
  dead end at sign-in somewhere to go.

## Probes (2026-10-10, x86 node): `probe_modify`

`probe_modify STEWARD_TEST STEWARD_TEST_ID` changes only those two names and restores
everything. It refuses to run if the identifier already exists. After each run the
owner and flags were back as they were, and the identifier was gone.

**As STEWARD_TEST's own persona (no privileges beyond its defaults), OpenVMS refuses:**
- `$SETUAI` on its own owner field: `%SYSTEM-F-NOPRIV`;
- `$ADD_IDENT`: `%RMS-E-PRV`.

**As a privileged caller:**
1. **`$SETUAI` counted fields need their full buffer.** OWNER with a buffer of
   length+1 bytes was refused with `%SYSTEM-F-BADPARAM`. With all 32 bytes (a
   length byte, the text, blank fill) it works. Every counted field is written at
   its declared size (OWNER, DEFDEV, DEFCLI and CLITABLES 32; DEFDIR and LGICMD 64).
2. **`$SETUAI` FLAGS** sets and restores cleanly. It writes the whole longword, so
   Steward reads, changes the bits asked for, and writes back.
3. **`$ADD_IDENT` with value 0** lets OpenVMS choose the value (`%X80010010`, then
   `%X80010011` on the next run: the next free one). `$ADD_HOLDER` twice gives
   `DUPIDENT`, and `$REM_HOLDER` of a holding that does not exist gives `NOSUCHID`.
4. **A holding's attributes are masked by its identifier's.** `$MOD_HOLDER` setting
   RESOURCE returned success but changed nothing while the identifier lacked
   RESOURCE. With RESOURCE on the identifier, the holding showed it. Clearing it on
   the identifier cleared it on the holding. Steward refuses (422) a holding
   attribute the identifier does not have, rather than let OpenVMS drop it silently.
5. **`$MOD_IDENT`** renames (the new name resolves to the same value) and sets
   attributes.
6. **`$REM_IDENT` of an identifier that is still held succeeds and removes the holder
   records too**, as `AUTHORIZE REMOVE/IDENTIFIER` does. A delete in Steward
   therefore shows the holders first and asks for confirmation.
