$! LOGIN.COM - the Steward service account's login procedure: it does nothing.
$! The account is RESTRICTED, and LOGINOUT refuses a restricted account whose login
$! procedure is missing (%DCL-E-NOCMDPROC; PHASE1.md). STEWARD$CONFIGURE copies this
$! to the account's default directory, readable but not writable by the account.
$ exit 1
