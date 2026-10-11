$! STEWARD_LNM.COM - list logical names as the user this process runs as (D14).
$!
$! Steward creates a short-lived detached process, under the viewer's persona, on
$! this procedure: OpenVMS has no service that lists a table, and SHOW LOGICAL runs
$! as whoever runs it, so OpenVMS decides what the viewer sees (D2). Steward sends no
$! commands, only data: its process name is STW<request>_<reply>, the unit numbers of
$! two mailboxes. It reads the table and the pattern from the first, checks both
$! again, and writes the listing to the second, then a last line %%END%%.
$!
$ set noon
$ if f$trnlnm("STEWARD_LNM_VERIFY") .nes. "" then set verify
$ set message/nofacility/noseverity/noidentification/notext
$ prc = f$edit(f$getjpi("", "PRCNAM"), "TRIM")
$ if f$extract(0, 3, prc) .nes. "STW" then exit
$ units = prc - "STW"
$ req = "_MBA" + f$element(0, "_", units) + ":"
$ rep = "_MBA" + f$element(1, "_", units) + ":"
$ open/read r 'req'
$ read/end_of_file=done r table
$ read/end_of_file=done r pattern
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
$ set message/facility/severity/identification/text
$ show logical/full/table='table'/output='rep' 'pattern'
$done:
$ open/write w 'rep'
$ write w "%%END%%"
$ close w
$ logout/brief
