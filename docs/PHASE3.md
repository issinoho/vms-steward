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

## Probes: passwords (2026-10-10)

- **`$SETUAI UAI$_PASSWORD` (plaintext; the system hashes it)** enforces the account's
  minimum length. Too short is refused with `%SYSTEM-F-INVPWDLEN`, and nothing
  changes. This was run by the user with `probe_password SET`.
- **`$ACM CHANGE_PASSWORD`, non-dialogue, needs `ACME$_NEW_PASSWORD_FLAGS`.** Without
  it `$ACMW` itself returns `%SYSTEM-F-INSFARG` before looking at any password.
  `probe_acmchg` found this using a made-up wrong password: with the item present,
  the ACMESB said `ACME-E-AUTHFAILURE` / `LOGIN-F-INVPWD`.
- **A failed CHANGE_PASSWORD is charged to the account, not to the client.** The
  attempt above left `USERNAME SUSPECT STEWARD_TEST`, although a remote host was
  supplied. A failed sign-in (`AUTHENTICATE_PRINCIPAL`) is charged to the client
  (PHASE1.md). If Steward exposed CHANGE_PASSWORD directly, anyone could lock an
  account by guessing. So Steward first checks the current password with
  AUTHENTICATE_PRINCIPAL (failures charged to the client, as at sign-in), and calls
  CHANGE_PASSWORD only after that succeeds.
- **What the user's runs showed (probe_password, 2026-10-10):**
  - An administrator's `$SETUAI UAI$_PASSWORD` sets the password date to *now* and
    leaves the password valid. For "set and pre-expire" (AUTHORIZE's `/PWDEXPIRED`)
    Steward also sets `UAI$_PWD_DATE` to -1.
  - The user's own CHANGE_PASSWORD succeeded and recorded the time.
  - A change with a short new password came back `AUTHFAILURE` / `LOGIN-F-INVPWD`,
    which is also what a wrong current password gives, so the run cannot say which
    it was. Steward's flow removes the doubt: it checks the current password first,
    and checks the new password against the account's minimum length before calling
    `$ACM`.
- **The service account can call CHANGE_PASSWORD.** Run as STEWARD (IMPERSONATE,
  TMPMBX, NETMBX; SYSPRV off) with a wrong password, `$ACMW` returned normally, and
  the ACMESB said `AUTHFAILURE`. As with sign-in, the reason is hidden from a caller
  without SYSPRV. A *successful* change as the service is verified at the phase exit.

## Browser exit checks and the 0.1.0 release (2026-10-11)

The user's first browser run (as STEWARD_ADM) sent no change request: the lighttpd log
shows the user page loaded and no PATCH. The user reported that the dialog opened and
Save did nothing. It did not reproduce on the dev server, with stub data shaped like
the real record, in headless Firefox. Before it was found, the user asked to stop and
release what exists as an early test ("everything looks good from here"). So Phase 3
ships in 0.1.0 with its browser checks still open. If the Save failure shows up again,
the next step is the browser console's output.

0.1.0 was installed from its PCSI kit on the x86 node and set up with
STEWARD$CONFIGURE for the existing STEWARD account. The pool was started with
STEWARD$CONTROL (current privileges DETACH, TMPMBX, NETMBX), and the test lighttpd
serves the generated STEWARD.CONF. Through nginx proxy manager:
- the page, its scripts and styles came back 200 with the right types, despite PCSI's
  upper-case file names;
- the CSP and X-Frame-Options headers were present;
- the API answered through the gateway secret;
- a failed sign-in was refused and audited in the new data directory, with the client
  address.
