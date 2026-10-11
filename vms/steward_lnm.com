$! STEWARD_LNM.COM - list logical names as the user this process runs as (D14).
$!
$! Steward creates a short-lived detached process, under the viewer's persona, on
$! this procedure: OpenVMS has no service that lists a table, and SHOW LOGICAL runs
$! as whoever runs it, so OpenVMS decides what the viewer sees (D2). Steward sends no
$! commands, only data: its process name is STW<request>_<reply>, the unit numbers of
$! two mailboxes. It reads the table, the pattern and the privileges switched on in
$! the session ("-" for none) from the first, checks them again, and writes the listing to the second, then a last line "%%END%% <status>":
$! SHOW LOGICAL's own exit status, in hexadecimal.
$!
$ set noon
$ set message/nofacility/noseverity/noidentification/notext
$ prc = f$edit(f$getjpi("", "PRCNAM"), "TRIM")
$ if f$extract(0, 3, prc) .nes. "STW" then exit
$ units = prc - "STW"
$ req = "_MBA" + f$element(0, "_", units) + ":"
$ rep = "_MBA" + f$element(1, "_", units) + ":"
$ open/read r 'req'
$ read/end_of_file=done r table
$ read/end_of_file=done r pattern
$ read/end_of_file=done r privs
$ close r
$! Only the characters of a table name and a wildcard pattern: nothing that DCL
$! would read as a qualifier, a symbol or a second command.
$ ok = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_*%"
$ s = table + pattern
$ if f$length(table) .lt. 1 .or. f$length(table) .gt. 31 .or. f$length(pattern) .lt. 1 .or. f$length(pattern) .gt. 255 then goto done
$ i = 0
$check:
$ if i .ge. f$length(s) then goto run
$ if f$locate(f$extract(i, 1, s), ok) .ge. f$length(ok) then goto done
$ i = i + 1
$ goto check
$run:
$! The privileges the user switched on in Steward (D9), as they could at a terminal:
$! OpenVMS grants only those the account is authorized for.
$ if privs .eqs. "-" then goto show
$ okp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_,"
$ if f$length(privs) .gt. 400 then goto done
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
$ show logical/full/table='table'/output='rep' 'pattern'
$ st = f$integer($status)        ! $STATUS is a string, "%X00000001"
$done:
$ if f$type(st) .eqs. "" then st = 20       ! SS$_BADPARAM: refused above
$ open/write w 'rep'
$ write w "%%END%% ", f$fao("!XL", st)
$ close w
$ logout/brief
