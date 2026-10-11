$! STEWARD$SHUTDOWN.COM - stop the Steward pool at system shutdown. Add to
$! SYS$MANAGER:SYSHUTDWN.COM:
$!     $ @SYS$STARTUP:STEWARD$SHUTDOWN.COM
$ set noon
$ if f$trnlnm("STEWARD$ROOT") .eqs. "" then exit 1
$ if f$search("SYS$MANAGER:STEWARD$CONFIG.COM") .eqs. "" then exit 1
$ @STEWARD$ROOT:[COM]STEWARD$CONTROL STOP
$ exit 1
