$! phase13b_pool.com - Phase 13b on a VMS node: STEWARD_POOL.COM starts, lists and
$! stops the recorder, in a test pool of no FastCGI processes run from the work
$! directory ([.P13BRUN], base port 19390): never the installed pool. Run in batch by
$! tests/vms/phase13b_live.py.
$ set noon
$ say = "write sys$output"
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$! Not "run": the pool procedure sees this job's symbols, and uses RUN/DETACHED.
$ tdir = here - "]" + ".P13BRUN]"
$ if f$search("P13BRUN.DIR") .eqs. "" then create/directory 'tdir'
$ if f$search(tdir + "MONITOR.DAT") .nes. "" then delete/nolog 'tdir'MONITOR.DAT;*
$ open/write s 'tdir'STEWARD_SETTINGS.COM
$ write s "$ define/process/nolog STEWARD_RECORD_SECS ""5"""
$ write s "$ define/process/nolog STEWARD_RECORD_DAYS ""1"""
$ close s
$ pool = here - "]" + ".VMS]STEWARD_POOL.COM"
$ image = here - "]" + ".BUILD]STEWARD.EXE"
$ ap = "$" + here - "]" + ".BUILD]API_PROBE.EXE"
$ say "==START=="
$ @'pool' START 0 19390 "''tdir'" "''image'"
$ wait 00:00:20
$ say "==STATUS=="
$ @'pool' STATUS 0 19390 "''tdir'"
$ define/process/nolog API_PROBE_MONITOR_FILE 'tdir'MONITOR.DAT
$ say "==HIST=="
$ ap STEWARD_TEST - "/api/v1/monitor/history?minutes=1&points=100"
$ deassign/process API_PROBE_MONITOR_FILE
$ say "==STOP=="
$ @'pool' STOP 0 19390 "''tdir'"
$ wait 00:00:02
$ say "==AFTER=="
$ @'pool' STATUS 0 19390 "''tdir'"
$ say "==PROT== ", f$file_attributes(tdir + "MONITOR.DAT", "PRO")
$!
$ say "==OFFSTART=="
$ open/write s 'tdir'STEWARD_SETTINGS.COM
$ write s "$ define/process/nolog STEWARD_RECORD_SECS ""0"""
$ close s
$ deassign/process STEWARD_RECORD_SECS
$ @'pool' START 0 19390 "''tdir'" "''image'"
$! The test pool's directory goes: nothing of it is wanted after the run.
$ tlogs = tdir - "]" + ".LOGS]"
$ delete/nolog 'tlogs'*.*;*
$ delete/nolog 'tdir'*.*;*/exclude=LOGS.DIR
$ set security/protection=(o:rwed) 'tdir'LOGS.DIR;1
$ delete/nolog 'tdir'LOGS.DIR;1
$ set security/protection=(o:rwed) P13BRUN.DIR;1
$ delete/nolog P13BRUN.DIR;1
$ say "==END=="
$ exit 1
