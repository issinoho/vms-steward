$! STEWARD_SYSGEN.COM - list the system parameters as the user this process runs as
$! (Phase 10, D18, through the D14 helper). OpenVMS has no service that gives SYSGEN's
$! defaults, limits and units; SYSGEN SHOW prints them, and any user may run it.
$! Steward sends no commands, only data: its process name is
$! STW<request><reply><random>, the unit numbers of two mailboxes and a random part, 4
$! hex digits each. It reads the privileges switched on in the session ("-" for none)
$! from the first, checks them, and has SYSGEN SHOW/ALL write to the second, then a
$! last line "%%END%% <status>": SYSGEN's exit status, in hexadecimal.
$!
$! The viewer's SYLOGIN and LOGIN.COM have run first: none of their symbols, global
$! or local, reaches this level after the next line (a global SET symbol would act on
$! that line itself: security.md, 2026-10-13).
$ set symbol/scope=(nolocal,noglobal)
$ set noon
$ set message/nofacility/noseverity/noidentification/notext
$ prc = f$edit(f$getjpi("", "PRCNAM"), "TRIM")
$! STW, then the request and reply mailbox units and a random part, 4 hex digits each.
$ if f$extract(0, 3, prc) .nes. "STW" .or. f$length(prc) .ne. 15 then exit
$ req = "_MBA" + f$string(f$integer("%X" + f$extract(3, 4, prc))) + ":"
$ rep = "_MBA" + f$string(f$integer("%X" + f$extract(7, 4, prc))) + ":"
$ open/read/error=done r 'req'
$ read/end_of_file=done/error=done r privs
$ close r
$! The privileges the user switched on in Steward (D9), as they could at a terminal:
$! OpenVMS grants only those the account is authorized for.
$ if privs .eqs. "-" then goto show
$ okp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_,"
$ if f$length(privs) .lt. 1 .or. f$length(privs) .gt. 400 then goto done
$ i = 0
$checkp:
$ if i .ge. f$length(privs) then goto setp
$ if f$locate(f$extract(i, 1, privs), okp) .ge. f$length(okp) then goto done
$ i = i + 1
$ goto checkp
$setp:
$ set process/privilege=('privs')
$show:
$! SYSGEN's commands are data lines, which DCL does not substitute into: the reply
$! mailbox is named for its SET/OUTPUT through a user-mode logical name, which lasts
$! for SYSGEN's run only.
$ set message/facility/severity/identification/text
$ define/user_mode/nolog steward_sysgen_reply 'rep'
$ mcr sysgen
SET/OUTPUT=STEWARD_SYSGEN_REPLY
SHOW/ALL
$ st = f$integer($status)        ! $STATUS is a string, "%X00000001"
$done:
$ if f$type(st) .eqs. "" then st = 20       ! SS$_BADPARAM: refused above
$ open/write w 'rep'
$ write w "%%END%% ", f$fao("!XL", st)
$ close w
$ logout/brief
