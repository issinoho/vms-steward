$! STEWARD$CONTROL.COM - start, stop and look after the Steward pool
$!
$! Usage (as SYSTEM: CMKRNL to submit as the service account, WORLD to stop it):
$!   @STEWARD$ROOT:[COM]STEWARD$CONTROL START     start the pool as the service account
$!   @STEWARD$ROOT:[COM]STEWARD$CONTROL STOP
$!   @STEWARD$ROOT:[COM]STEWARD$CONTROL RESTART   after changing STEWARD_SETTINGS.COM
$!   @STEWARD$ROOT:[COM]STEWARD$CONTROL STATUS    processes, their privileges, and the
$!                                                end of the audit log
$!
$! Site settings: SYS$MANAGER:STEWARD$CONFIG.COM (STEWARD$CONFIGURE). The pool's
$! processes are named STEWARD_<port>; each logs to <data>[.RUN.LOGS].
$!
$ set noon
$ say = "write sys$output"
$ op = f$edit(p1, "UPCASE,TRIM")
$ if f$search("SYS$MANAGER:STEWARD$CONFIG.COM") .eqs. ""
$ then
$   say "STEWARD: no SYS$MANAGER:STEWARD$CONFIG.COM; run @STEWARD$ROOT:[COM]STEWARD$CONFIGURE first"
$   exit 44
$ endif
$ @SYS$MANAGER:STEWARD$CONFIG.COM
$ rundir = steward_data - "]" + ".RUN]"
$ pool = "STEWARD$ROOT:[COM]STEWARD_POOL.COM"
$ image = "STEWARD$ROOT:[BIN]STEWARD.EXE"
$ if op .eqs. "START" then goto start
$ if op .eqs. "STOP" then goto stop
$ if op .eqs. "RESTART" then goto restart
$ if op .eqs. "STATUS" then goto status
$ say "usage: @STEWARD$ROOT:[COM]STEWARD$CONTROL START|STOP|RESTART|STATUS"
$ exit 44
$!
$start:
$! The pool's own procedure runs as the account, so the processes it creates log in
$! as the account (RUN/DETACHED/AUTHORIZE: its UAF privileges and quotas).
$ submit/user='steward_account'/noprint/name=STEWARD_START -
      /log_file='rundir'STEWARD_START.LOG 'pool' -
      /parameters=("START","''steward_count'","''steward_base'","''rundir'","''image'")
$ if .not. $status then exit $status
$ say "STEWARD: start submitted as ", steward_account, " (log ", rundir, "STEWARD_START.LOG)"
$ exit 1
$!
$restart:
$ @'pool' STOP 'steward_count' 'steward_base' "''rundir'"
$ goto start
$!
$stop:
$ @'pool' STOP 'steward_count' 'steward_base' "''rundir'"
$ exit 1
$!
$status:
$ @'pool' STATUS 'steward_count' 'steward_base' "''rundir'"
$ audit = rundir + "AUDIT.LOG"
$ if f$search(audit) .nes. ""
$ then
$   say ""
$   say "Last audit records (", audit, "):"
$   type/tail=8 'audit'
$ endif
$ exit 1
