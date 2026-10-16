$! STEWARD_LICENSE.COM - list the licences as the user this process runs as (Phase 11,
$! D19, through the D14 helper). OpenVMS has no documented service that lists them;
$! SHOW LICENSE shows the loaded ones to any user, LICENSE LIST the database to those
$! OpenVMS lets read it (SYSPRV, READALL, UIC group 1).
$! Steward sends no commands, only data: its process name is
$! STW<request><reply><random>, the unit numbers of two mailboxes and a random part, 4
$! hex digits each. It reads the privileges switched on in the session ("-" for none)
$! from the first, checks them, and writes to the second each command's output, marked
$! "%%PART%% <name>" before and "%%STATUS%% <status>" after (hexadecimal), then a last
$! line "%%END%% 1"; "%%END%% <status>" if it refused the privileges.
$!
$! The viewer's SYLOGIN and LOGIN.COM have run first: none of their symbols, global
$! or local, reaches this level.
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
$ set message/facility/severity/identification/text
$ open/write w 'rep'
$ write w "%%PART%% LOADED"
$ close w
$ show license/full/output='rep'
$ st = f$integer($status)        ! $STATUS is a string, "%X00000001"
$ open/write w 'rep'
$ write w "%%STATUS%% ", f$fao("!XL", st)
$ write w "%%PART%% CHARGE"
$ close w
$ show license/unit_requirements/output='rep'
$ st = f$integer($status)
$ open/write w 'rep'
$ write w "%%STATUS%% ", f$fao("!XL", st)
$ write w "%%PART%% DATABASE"
$ close w
$ license list/full/output='rep'
$ st = f$integer($status)
$ open/write w 'rep'
$ write w "%%STATUS%% ", f$fao("!XL", st)
$ close w
$ st = 1
$done:
$ if f$type(st) .eqs. "" then st = 20       ! SS$_BADPARAM: refused above
$ open/write w 'rep'
$ write w "%%END%% ", f$fao("!XL", st)
$ close w
$ logout/brief
