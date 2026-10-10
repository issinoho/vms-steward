$! LIGHTTPD_TEST.COM - a separate lighttpd for testing Steward, from a work
$! directory, using the installed VMSLIGHTTPD image but its own configuration.
$! It never touches the site's own lighttpd, its configuration or its files.
$!
$!   @LIGHTTPD_TEST START conf-unix-path log-file
$!   @LIGHTTPD_TEST STOP
$!   @LIGHTTPD_TEST STATUS
$!
$! The process is detached through LOGINOUT, named STEWARD_HTTPD, and runs lighttpd
$! in the foreground (-D) as VMSLIGHTTPD$SERVER.COM does. EXTENDED parse style keeps
$! "-D" upper case (see that procedure).
$ set noon
$ say = "write sys$output"
$ op = f$edit(p1, "UPCASE,TRIM")
$ name = "STEWARD_HTTPD"
$ ctx = ""
$ x = f$context("PROCESS", ctx, "PRCNAM", name, "EQL")
$ pid = f$pid(ctx)
$ if pid .nes. "" then x = f$context("PROCESS", ctx, "CANCEL")
$ if op .eqs. "STATUS"
$ then
$   if pid .eqs. "" then say "LIGHTTPD_TEST: not running"
$   if pid .nes. "" then say "LIGHTTPD_TEST: ", name, " pid ", pid, " state ", f$getjpi(pid, "STATE")
$   exit 1
$ endif
$ if op .eqs. "STOP"
$ then
$   if pid .nes. "" then stop/id='pid'
$   say "LIGHTTPD_TEST: stopped"
$   exit 1
$ endif
$ if op .nes. "START" .or. p2 .eqs. "" .or. p3 .eqs. ""
$ then
$   say "usage: @LIGHTTPD_TEST START conf-unix-path log-file | STOP | STATUS"
$   exit 44
$ endif
$ if pid .nes. ""
$ then
$   say "LIGHTTPD_TEST: already running (", pid, ")"
$   exit 1
$ endif
$ com = f$parse(p3,,,"DEVICE","NO_CONCEAL") + f$parse(p3,,,"DIRECTORY","NO_CONCEAL") + "LIGHTTPD_TEST_RUN.COM"
$ open/write w 'com'
$ write w "$ set noon"
$ write w "$ set process/parse_style=extended"
$ write w "$ lighttpd = ""$VMSLIGHTTPD$ROOT:[BIN]LIGHTTPD.EXE"""
$ write w "$ write sys$output ""LIGHTTPD_TEST start "", f$time()"
$ write w "$ lighttpd ""-D"" ""-f"" """, p2, """"
$ write w "$ write sys$output ""LIGHTTPD_TEST exit "", $status, "" "", f$time()"
$ close w
$ run/detached sys$system:loginout.exe /input='com' /output='p3' /error='p3' -
      /process_name='name' /buffer_limit=200000 /file_limit=200 /io_buffered=200 -
      /io_direct=200 /queue_limit=64 /enqueue_limit=2000 /ast_limit=200 -
      /page_file=200000 /working_set=4096 /maximum_working_set=16384 /extent=32768
$ if .not. $status
$ then
$   say "LIGHTTPD_TEST: could not create ", name
$   exit 44
$ endif
$ say "LIGHTTPD_TEST: started ", name
$ exit 1
