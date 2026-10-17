$! phase13b_rec.com - Phase 13b on a VMS node: the recorder (steward -r) run for 40
$! seconds at 5 s into a scratch recording in [.BUILD], then read back through the
$! real dispatcher and platform (API_PROBE) as STEWARD_TEST. Run in batch by
$! tests/vms/phase13b_live.py (WAIT is fine in batch; never over ssh). The recorder is
$! a subprocess of this job, stopped by its PID at the end.
$ set noon
$ say = "write sys$output"
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ build = here - "]" + ".BUILD]"
$ ap = "$" + build + "API_PROBE.EXE"
$ rec = "$" + build + "STEWARD.EXE"
$ file = build + "P13B_MONITOR.DAT"
$ if f$search(file) .nes. "" then delete/nolog 'file';*
$ if f$search(build + "P13B_REC.LOG") .nes. "" then delete/nolog 'build'P13B_REC.LOG;*
$!
$ define/process/nolog STEWARD_RECORD_SECS "0"
$ rec "-r"
$ say "==OFF== ", $status
$ define/process/nolog STEWARD_RECORD_SECS "2"
$ rec "-r"
$ say "==BADSECS== ", $status
$!
$ define/process/nolog STEWARD_MONITOR_FILE 'file'
$ define/process/nolog STEWARD_RECORD_SECS "5"
$ define/process/nolog STEWARD_RECORD_DAYS "1"
$ say "==PARENTPRIV== ", f$extract(0, 200, f$getjpi("", "CURPRIV"))   ! >255 characters overflows a DCL token
$ spawn/nowait/process=STW_P13B_REC/output='build'P13B_REC.LOG rec "-r"
$ wait 00:00:03
$ ctx = ""
$ x = f$context("PROCESS", ctx, "PRCNAM", "STW_P13B_REC", "EQL")
$ pid = f$pid(ctx)
$ if pid .nes. "" then x = f$context("PROCESS", ctx, "CANCEL")
$ say "==PID== ", pid
$ wait 00:00:40
$ if pid .nes. ""
$ then
$   say "==CURPRIV== ", f$getjpi(pid, "CURPRIV")
$   say "==PROCPRIV== ", f$getjpi(pid, "PROCPRIV")
$   say "==IMAGE== ", f$getjpi(pid, "IMAGNAME")
$ endif
$ define/process/nolog API_PROBE_MONITOR_FILE 'file'
$ say "==HIST=="
$ ap STEWARD_TEST - "/api/v1/monitor/history?minutes=2&points=100"
$ say "==LIVE=="
$ ap STEWARD_TEST - "/api/v1/monitor"
$ say "==THIN=="
$ ap STEWARD_TEST - "/api/v1/monitor/history?minutes=1&points=2"
$ if pid .nes. "" then stop/id='pid'
$ say "==STOPPED== ", pid
$ deassign/process API_PROBE_MONITOR_FILE
$ say "==NOFILE=="
$ ap STEWARD_TEST - "/api/v1/monitor/history"
$ say "==DIR=="
$ directory/size=all/protection 'file'
$ say "==RECLOG=="
$ type 'build'P13B_REC.LOG
$ say "==END=="
$ exit 1
