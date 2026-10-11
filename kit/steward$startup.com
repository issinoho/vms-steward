$! STEWARD$STARTUP.COM - Steward for OpenVMS at system startup
$!
$! Usage (as SYSTEM):
$!   @SYS$STARTUP:STEWARD$STARTUP          from SYSTARTUP_VMS.COM: define STEWARD$ROOT,
$!                                         and start the pool if
$!                                         SYS$MANAGER:STEWARD$CONFIG.COM says AUTOSTART
$!                                         for this node
$!   @SYS$STARTUP:STEWARD$STARTUP INSTALL  define only (PCSI postinstall)
$!   @SYS$STARTUP:STEWARD$STARTUP REMOVE   stop the pool, deassign
$!
$! Steward installs no images: the pool runs with the service account's own
$! privileges (README.VMS, DECISIONS D2).
$!
$ set noon
$ op = f$edit(p1, "UPCASE,TRIM")
$ if op .eqs. "REMOVE" then goto remove
$! This procedure sits in <destination>[SYS$STARTUP]; the product is in
$! <destination>[STEWARD] (as VMSLIGHTTPD$STARTUP finds its root).
$ proc = f$environment("PROCEDURE")
$ dev = f$parse(proc,,,"DEVICE","NO_CONCEAL")
$ dir = f$edit(f$parse(proc,,,"DIRECTORY","NO_CONCEAL"), "UPCASE") - "]["
$ root = dir - "SYS$STARTUP]" + "STEWARD.]"
$ if root .eqs. dir + "STEWARD.]"
$ then
$   write sys$error "STEWARD$STARTUP: expected to be in a [SYS$STARTUP] directory, not ''dir'"
$   exit 44
$ endif
$ root = dev + (root - ".000000")
$ define/system/executive_mode/translation_attributes=concealed STEWARD$ROOT 'root'
$ if f$search("STEWARD$ROOT:[BIN]STEWARD.EXE") .eqs. ""
$ then
$   write sys$error "STEWARD$STARTUP: no STEWARD$ROOT:[BIN]STEWARD.EXE (root ", root, ")"
$   exit 44
$ endif
$ if op .eqs. "INSTALL" then exit 1
$!
$! boot: start if the site settings ask for it on this node
$ if f$search("SYS$MANAGER:STEWARD$CONFIG.COM") .eqs. "" then exit 1
$ @SYS$MANAGER:STEWARD$CONFIG.COM
$ node = f$edit(f$getsyi("NODENAME"), "UPCASE")
$ if f$edit(steward_autostart, "UPCASE") .nes. "YES" then exit 1
$ if steward_node .nes. "" .and. f$edit(steward_node, "UPCASE") .nes. node then exit 1
$ @STEWARD$ROOT:[COM]STEWARD$CONTROL START
$ exit 1
$!
$remove:
$ if f$trnlnm("STEWARD$ROOT") .nes. ""
$ then
$   if f$search("STEWARD$ROOT:[COM]STEWARD$CONTROL.COM") .nes. "" .and. -
       f$search("SYS$MANAGER:STEWARD$CONFIG.COM") .nes. "" then -
       @STEWARD$ROOT:[COM]STEWARD$CONTROL STOP
$   deassign/system/executive_mode STEWARD$ROOT
$ endif
$ exit 1
