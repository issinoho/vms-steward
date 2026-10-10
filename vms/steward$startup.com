$! STEWARD$STARTUP.COM - define STEWARD$ROOT and start the Steward pool.
$!
$!   @STEWARD$STARTUP root-directory      e.g. DKA100:[STEWARD]
$!
$! The STEWARD account is RESTRICTED, and LOGINOUT refuses a restricted account
$! whose login procedure is missing (%DCL-E-NOCMDPROC, "captive command procedure",
$! 2026-10-10), so the kit installs a do-nothing SYS$LOGIN:LOGIN.COM that the account
$! can read but not change: (S:RWE,O:RE,G,W).
$!
$! Not yet exercised: the installed layout arrives with the PCSI kit (Phase 5), and
$! until then the pool is started by hand from the work directory.
$!
$! Run from SYSTARTUP_VMS.COM (or by hand, by SYSTEM). The pool runs as the
$! service account STEWARD, which holds IMPERSONATE, TMPMBX and NETMBX only
$! (DECISIONS D2); SUBMIT/USER needs CMKRNL, which SYSTEM has. The pool's state
$! (sessions, audit log, settings) lives in STEWARD$ROOT:[RUN], owned by STEWARD and
$! protected (S:RWE,O:RWED,G,W) so nobody else can read the session store or alter
$! the audit log.
$!
$ set noon
$ root = p1
$ if root .eqs. ""
$ then
$   write sys$output "usage: @STEWARD$STARTUP root-directory"
$   exit 44
$ endif
$ root = f$parse(root,,,"DEVICE","NO_CONCEAL") + f$parse(root,,,"DIRECTORY","NO_CONCEAL")
$ root = root - "]" + ".]"
$ define/system/exec/translation=concealed/nolog STEWARD$ROOT 'root'
$ if f$search("STEWARD$ROOT:[000000]RUN.DIR") .eqs. "" then -
      create/directory/owner=STEWARD/protection=(s:rwe,o:rwed,g,w) STEWARD$ROOT:[RUN]
$ submit/user=STEWARD/noprint/queue=sys$batch/log_file=STEWARD$ROOT:[RUN]STEWARD_STARTUP.LOG -
      STEWARD$ROOT:[COM]STEWARD_POOL.COM /parameters=("START","2","19300","STEWARD$ROOT:[RUN]")
$ exit 1
