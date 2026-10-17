$! STEWARD_ERRLOG.COM - translate the error log as the user this process runs as
$! (Phase 14, D23, through the D14 helper). ERRLOG.SYS's format is not documented and
$! the classic ANALYZE/ERROR_LOG is not on x86, so ELV translates it; OpenVMS decides
$! whether the viewer may read the file (SYSPRV, or the SYSTEM group). Without access
$! ELV prints %ELV-E-FILOPNERR (with -RMS-E-FNF) and still exits with success: Steward
$! reads its messages (NOTES.md). ELV ignores a SYS$OUTPUT redefined for it (it wrote an
$! empty file, NOTES.md), so it is given the reply mailbox with /OUTPUT=; its messages
$! go to SYS$ERROR, the mailbox for that one image (DEFINE/USER).
$! Steward sends no commands, only data: its process name is
$! STW<request><reply><random>, the unit numbers of two mailboxes and a random part, 4
$! hex digits each. It reads from the first the privileges switched on in the session
$! ("-" for none), what to do (LIST or ENTRY), a number (LIST: the days back, 0 for
$! the whole file; ENTRY: the event) and the file (SYS$ERRORLOG:ERRLOG.SYS, or a renamed
$! one, D24: Steward fixes the directory and checks the name), checks them again, and
$! writes ELV's output to the
$! second, marked "%%PART%% <name>" before and "%%STATUS%% <status>" after
$! (hexadecimal), then a last line "%%END%% 1"; "%%END%% <status>" if it refused.
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
$ read/end_of_file=done/error=done r op
$ read/end_of_file=done/error=done r num
$ read/end_of_file=done/error=done r file
$ close r
$! What to do, one of two words; the number digits only, at most 10 of them (DCL's
$! delta time takes at most 9999 days: Steward sends no more).
$ if op .nes. "LIST" .and. op .nes. "ENTRY" then goto done
$ if f$length(num) .lt. 1 .or. f$length(num) .gt. 10 then goto done
$ i = 0
$checkn:
$ if i .ge. f$length(num) then goto checkf
$ if f$locate(f$extract(i, 1, num), "0123456789") .ge. 10 then goto done
$ i = i + 1
$ goto checkn
$! The file: a device, a directory and a name, nothing DCL would read as a qualifier,
$! a symbol, a list or a second command.
$checkf:
$ file = f$edit(file, "UPCASE")
$ okf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_.:[]"
$ if f$length(file) .lt. 1 .or. f$length(file) .gt. 200 then goto done
$ i = 0
$checkf1:
$ if i .ge. f$length(file) then goto privs
$ if f$locate(f$extract(i, 1, file), okf) .ge. f$length(okf) then goto done
$ i = i + 1
$ goto checkf1
$privs:
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
$ n = f$integer(num)
$ open/write w 'rep'
$ if op .eqs. "LIST" then write w "%%PART%% EVENTS"
$ if op .eqs. "ENTRY" then write w "%%PART%% ENTRY"
$ close w
$ define/user sys$output 'rep'
$ define/user sys$error 'rep'
$ if op .eqs. "LIST" .and. n .eq. 0 then analyze/error_log/elv translate/one_line/output='rep' 'file'
$ if op .eqs. "LIST" .and. n .gt. 0 then analyze/error_log/elv translate/one_line/since=-'n'-/output='rep' 'file'
$ if op .eqs. "ENTRY" then analyze/error_log/elv translate/entry=(start:'n',end:'n')/output='rep' 'file'
$ st = f$integer($status)        ! $STATUS is a string, "%X00000001"
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
