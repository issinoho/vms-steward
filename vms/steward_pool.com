$! STEWARD_POOL.COM - a pool of Steward FastCGI processes for lighttpd.
$!
$! Usage:  @STEWARD_POOL START|STOP|STATUS [count] [base-port] [run-dir] [image]
$!   count      number of processes (default 2)
$!   base-port  first TCP port; process n listens on 127.0.0.1:base-port+n
$!              (default 19300)
$!   run-dir    directory for the pool's state (default: this procedure's
$!              directory). It holds:
$!                STEWARD_SETTINGS.COM  site settings, run by each process
$!                SESSIONS.DAT          shared session store (created on first use)
$!                AUDIT.LOG             shared audit log (created on first use)
$!                MONITOR.DAT           the monitoring recording (D22)
$!                [.LOGS]               one log per process, and the stop file
$!   image      the server image (default STEWARD$ROOT:[BIN]STEWARD.EXE)
$!
$! The same shape as vms-lighttpd's PHP_POOL.COM (DECISIONS D1): each process is
$! detached through LOGINOUT, named STEWARD_<port>, and runs the image in a DCL
$! loop that restarts it if it exits; lighttpd's fastcgi.server lists the same
$! host:port pairs. STOP writes [.LOGS]POOL.STOP so the loops end, then stops the
$! processes.
$!
$! With the pool, the monitoring recorder (D22): STEWARD_R<base-port>, the same image
$! as "steward -r" in the same kind of loop, writing a reading a minute to
$! MONITOR.DAT. It switches its privileges off when it starts. STEWARD_RECORD_SECS
$! "0" in STEWARD_SETTINGS.COM leaves it unstarted; STOP stops it either way.
$!
$! Run it as the service account, which should hold IMPERSONATE, TMPMBX and NETMBX
$! and nothing else (D2), for example from the startup procedure:
$!   $ SUBMIT/USER=STEWARD/NOPRINT STEWARD$ROOT:[COM]STEWARD_POOL.COM /PARAMETERS=START
$! The detached processes run under whoever starts the pool.
$!
$ set noon
$! No symbol here may share a name with a DCL verb this procedure uses: a symbol
$! called RUN was substituted into RUN/DETACHED (%DCL-W-IVVERB, 2026-10-10) and the
$! pool reported "started" for processes that were never created.
$ say = "write sys$output"
$ op = f$edit(p1, "UPCASE,TRIM")
$ count = 2
$ if p2 .nes. "" then count = f$integer(p2)
$ base = 19300
$ if p3 .nes. "" then base = f$integer(p3)
$ rdir = p4
$ if rdir .eqs. "" then rdir = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + -
                            f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ rdir = f$parse(rdir,,,"DEVICE","NO_CONCEAL") + f$parse(rdir,,,"DIRECTORY","NO_CONCEAL")
$ i = f$locate("][", rdir)
$ if i .lt. f$length(rdir) then rdir = f$extract(0, i - 1, rdir) + "." + f$extract(i + 2, 999, rdir)
$ image = p5
$ if image .eqs. "" then image = "STEWARD$ROOT:[BIN]STEWARD.EXE"
$ rundir = rdir - "]"
$ logs = rundir + ".LOGS]"
$ stopfile = logs + "POOL.STOP"
$ if op .eqs. "START" then goto start
$ if op .eqs. "STOP" then goto stop
$ if op .eqs. "STATUS" then goto status
$ say "usage: @STEWARD_POOL START|STOP|STATUS [count] [base-port] [run-dir] [image]"
$ exit 44
$!
$start:
$ image = f$search(image)   ! a full file spec: the detached processes start elsewhere
$ if image .eqs. ""
$ then
$   say "STEWARD_POOL: no ", p5, " (default STEWARD$ROOT:[BIN]STEWARD.EXE)"
$   exit 44
$ endif
$ image = image - f$parse(image,,,"VERSION")
$ settings = rdir + "STEWARD_SETTINGS.COM"
$ if f$search(settings) .eqs. ""
$ then
$   say "STEWARD_POOL: no ", settings, " (copy STEWARD_SETTINGS.TEMPLATE and edit it)"
$   exit 44
$ endif
$ if f$search(rundir + "]LOGS.DIR") .eqs. "" then create/directory 'logs'
$ if f$search(stopfile) .nes. "" then delete/nolog 'stopfile';*
$ n = 0
$start_loop:
$ if n .ge. count then goto start_recorder
$ port = base + n
$ n = n + 1
$ name = "STEWARD_" + f$string(port)
$ gosub find_pid
$ if pid .nes. ""
$ then
$   say "STEWARD_POOL: ", name, " already running"
$   goto start_loop
$ endif
$ com = logs + name + ".COM"
$ open/write w 'com'
$ write w "$ set noon"
$! Files the server creates (session store, audit log) are private to the account,
$! whatever its default protection: they must not depend on the directory alone.
$ write w "$ set protection=(s:rwed,o:rwed,g,w)/default"
$ write w "$ define/process/nolog STEWARD_SESSION_FILE """, rdir, "SESSIONS.DAT"""
$ write w "$ define/process/nolog STEWARD_AUDIT_FILE """, rdir, "AUDIT.LOG"""
$ write w "$ define/process/nolog STEWARD_MONITOR_FILE """, rdir, "MONITOR.DAT"""
$ write w "$ @", settings
$ write w "$ steward = ""$", image, """"
$ write w "$loop:"
$ write w "$ if f$search(""", stopfile, """) .nes. """" then exit"
$ write w "$ write sys$output """, name, " start "", f$time()"
$ write w "$ steward ""-b"" ""127.0.0.1:", port, """"
$ write w "$ write sys$output """, name, " exit "", $status, "" "", f$time()"
$ write w "$ if f$search(""", stopfile, """) .nes. """" then exit"
$ write w "$ wait 00:00:01"
$ write w "$ goto loop"
$ close w
$! /AUTHORIZE: a full login, so the process takes its privileges and quotas from the
$! UAF. Without it, LOGINOUT copies the creator's privileges, and SYSPRV (authorized,
$! normally off: D2) would be missing from the authorized mask. LOGIN.COM must exist.
$ run/detached sys$system:loginout.exe /authorize /input='com' -
      /output='logs''name'.LOG /error='logs''name'.LOG -
      /process_name='name'
$ if .not. $status
$ then
$   say "STEWARD_POOL: could not create ", name
$   goto start_loop
$ endif
$ say "STEWARD_POOL: started ", name, " on 127.0.0.1:", port
$ goto start_loop
$!
$! The recorder, unless the settings turn it off (they define process logical names:
$! here, in this job, only to read that one).
$start_recorder:
$ @'settings'
$ if f$trnlnm("STEWARD_RECORD_SECS") .eqs. "0"
$ then
$   say "STEWARD_POOL: the recorder is off (STEWARD_RECORD_SECS 0)"
$   exit 1
$ endif
$ name = "STEWARD_R" + f$string(base)
$ gosub find_pid
$ if pid .nes. ""
$ then
$   say "STEWARD_POOL: ", name, " already running"
$   exit 1
$ endif
$ com = logs + name + ".COM"
$ open/write w 'com'
$ write w "$ set noon"
$ write w "$ set protection=(s:rwed,o:rwed,g,w)/default"
$ write w "$ define/process/nolog STEWARD_MONITOR_FILE """, rdir, "MONITOR.DAT"""
$ write w "$ @", settings
$ write w "$ steward = ""$", image, """"
$ write w "$loop:"
$ write w "$ if f$search(""", stopfile, """) .nes. """" then exit"
$ write w "$ write sys$output """, name, " start "", f$time()"
$ write w "$ steward ""-r"""
$ write w "$ write sys$output """, name, " exit "", $status, "" "", f$time()"
$ write w "$ if f$search(""", stopfile, """) .nes. """" then exit"
$! A minute, not a second: nothing waits on the recorder, and a setting it refuses
$! should not fill its log.
$ write w "$ wait 00:01:00"
$ write w "$ goto loop"
$ close w
$ run/detached sys$system:loginout.exe /authorize /input='com' -
      /output='logs''name'.LOG /error='logs''name'.LOG -
      /process_name='name'
$ if .not. $status
$ then
$   say "STEWARD_POOL: could not create ", name
$   exit 1
$ endif
$ say "STEWARD_POOL: started ", name, " (monitoring recorder)"
$ exit 1
$!
$stop:
$ if f$search(rundir + "]LOGS.DIR") .eqs. "" then create/directory 'logs'
$ open/write s 'stopfile'
$ close s
$ n = 0
$stop_loop:
$ if n .ge. count then goto stop_done
$ port = base + n
$ n = n + 1
$ name = "STEWARD_" + f$string(port)
$ gosub find_pid
$ if pid .eqs. ""
$ then
$   say "STEWARD_POOL: ", name, " not running"
$ else
$   stop/id='pid'
$   say "STEWARD_POOL: stopped ", name, " (", pid, ")"
$ endif
$ goto stop_loop
$stop_done:
$ name = "STEWARD_R" + f$string(base)
$ gosub find_pid
$ if pid .nes. ""
$ then
$   stop/id='pid'
$   say "STEWARD_POOL: stopped ", name, " (", pid, ")"
$ endif
$ delete/nolog 'stopfile';*
$ exit 1
$!
$status:
$ n = 0
$status_loop:
$ if n .gt. count then exit 1
$ port = base + n
$ n = n + 1
$ name = "STEWARD_" + f$string(port)
$ if n .gt. count then name = "STEWARD_R" + f$string(base)   ! last, the recorder
$ gosub find_pid
$ if pid .eqs. ""
$ then
$   say "STEWARD_POOL: ", name, " not running"
$ else
$   say "STEWARD_POOL: ", name, " pid ", pid, " user ", f$edit(f$getjpi(pid, "USERNAME"), "TRIM"), -
        " cpu ", f$getjpi(pid, "CPUTIM"), " state ", f$getjpi(pid, "STATE")
$   privs = f$getjpi(pid, "CURPRIV")
$   if f$length(privs) .gt. 200 then privs = f$extract(0, 200, privs) + ",..."
$   say "              privileges: ", privs   ! >255 characters overflows a DCL token
$ endif
$ goto status_loop
$!
$! pid: the PID of the process called <name>, or ""
$find_pid:
$ ctx = ""
$ x = f$context("PROCESS", ctx, "PRCNAM", name, "EQL")
$ pid = f$pid(ctx)
$ if pid .nes. "" then x = f$context("PROCESS", ctx, "CANCEL")
$ return
