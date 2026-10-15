$! PHASE8_JPI.COM - every process, as DCL sees it from a privileged process, for
$! tests/vms/phase8_live.py: PID|name|username|group,member (decimal)|base
$! priority|image. (F$GETJPI's UIC item gives identifier names, [SYSTEM], not numbers.)
$ ctx = ""
$loop:
$ pid = f$pid(ctx)
$ if pid .eqs. "" then exit 1
$ write sys$output "P|", pid, "|", f$getjpi(pid, "PRCNAM"), "|", -
    f$edit(f$getjpi(pid, "USERNAME"), "TRIM"), "|", f$getjpi(pid, "GRP"), ",", f$getjpi(pid, "MEM"), "|", -
    f$getjpi(pid, "PRIB"), "|", f$getjpi(pid, "IMAGNAME")
$ goto loop
