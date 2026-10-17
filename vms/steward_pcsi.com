$! STEWARD_PCSI.COM - find kits, or start an install or a removal, as the user this
$! process runs as (Phase 12b, D26, through the D14 helper).
$! FIND: PRODUCT FIND * /SOURCE=<dir> (no privilege needed), into the reply mailbox
$! (DEFINE/USER: PRODUCT has no /OUTPUT=), as part KITS. INSTALL or REMOVE: SUBMIT the
$! fixed job procedure Steward names (STEWARD_PCSI_JOB.COM, resolved by Steward) to
$! SYS$BATCH under this user's own name, which needs no privilege; the job does the
$! work, which can take minutes, logging to SYS$LOGIN:STEWARD_PCSI_<time>.LOG.
$! Steward sends no commands, only data: its process name is
$! STW<request><reply><random>, the unit numbers of two mailboxes and a random part, 4
$! hex digits each. It reads from the first nine lines: the privileges switched on in
$! the session ("-" for none), FIND, INSTALL or REMOVE, the source directory, the
$! producer, base, name and version, the destination directory ("-" for each not
$! given) and the job procedure; checks them, and answers on the second: FIND's
$! output marked "%%PART%% KITS" ... "%%STATUS%% <status>", or "%%SUBMIT%% <status>",
$! "%%ENTRY%% <entry>" and "%%LOG%% <log file name>"; then "%%END%% 1", or
$! "%%END%% <status>" if it refused.
$!
$! The viewer's SYLOGIN and LOGIN.COM have run first: none of their symbols, global
$! or local, reaches this level after the next line (a global SET symbol would act on
$! that line itself: security.md, 2026-10-13). No symbol here is named after a verb
$! it uses (CLAUDE.md).
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
$ read/end_of_file=done/error=done r p_op
$ read/end_of_file=done/error=done r p_src
$ read/end_of_file=done/error=done r p_prod
$ read/end_of_file=done/error=done r p_base
$ read/end_of_file=done/error=done r p_name
$ read/end_of_file=done/error=done r p_ver
$ read/end_of_file=done/error=done r p_dest
$ read/end_of_file=done/error=done r p_job
$ close r
$! Each checked: one of three words; directories and the job procedure as device,
$! directory and file names; the name's words as PCSI writes them. Nothing DCL would
$! read as a qualifier, a symbol, a list or a second command.
$ if p_op .nes. "FIND" .and. p_op .nes. "INSTALL" .and. p_op .nes. "REMOVE" then goto done
$ okd = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-.:[]"
$ okw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-."
$ p_job = f$edit(p_job, "UPCASE")
$ chk = p_src
$ chkset = okd
$ gosub check
$ if .not. ok then goto done
$ chk = p_dest
$ gosub check
$ if .not. ok then goto done
$ chk = p_job
$ gosub check
$ if .not. ok then goto done
$ chkset = okw
$ chk = p_prod
$ gosub check
$ if .not. ok then goto done
$ chk = p_base
$ gosub check
$ if .not. ok then goto done
$ chk = p_name
$ gosub check
$ if .not. ok then goto done
$ chk = p_ver
$ gosub check
$ if .not. ok then goto done
$! The privileges the user switched on in Steward (D9), as they could at a terminal:
$! OpenVMS grants only those the account is authorized for. The job is given them as
$! a parameter, which DCL limits to 255 characters.
$ if privs .eqs. "-" then goto work
$ okp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_,"
$ if f$length(privs) .lt. 1 .or. f$length(privs) .gt. 255 then goto done
$ i = 0
$checkp:
$ if i .ge. f$length(privs) then goto setp
$ if f$locate(f$extract(i, 1, privs), okp) .ge. f$length(okp) then goto done
$ i = i + 1
$ goto checkp
$setp:
$ set process/privilege=('privs')
$work:
$ set message/facility/severity/identification/text
$ if p_op .nes. "FIND" then goto start_job
$ if p_src .eqs. "-" then goto done
$ open/write w 'rep'
$ write w "%%PART%% KITS"
$ close w
$ define/user sys$output 'rep'
$ define/user sys$error 'rep'
$ product find * /source='p_src'
$ st = f$integer($status)        ! $STATUS is a string, "%X00000001"
$ open/write w 'rep'
$ write w "%%STATUS%% ", f$fao("!XL", st)
$ close w
$ st = 1
$ goto done
$!
$start_job:
$ if p_prod .eqs. "-" .or. p_base .eqs. "-" .or. p_name .eqs. "-" .or. p_job .eqs. "-" then goto done
$ if p_op .eqs. "INSTALL" .and. (p_src .eqs. "-" .or. p_ver .eqs. "-") then goto done
$! The job logs in to this user's login directory and writes its log there: without
$! one, SUBMIT fails with a status that has no message text (%X00C18324, seen on x86
$! 2026-10-17), so it is said here instead (RMS-E-DNF, 114762).
$ if f$parse(f$trnlnm("SYS$LOGIN")) .nes. "" then goto have_login
$ open/write w 'rep'
$ write w "%%SUBMIT%% ", f$fao("!XL", 114762)
$ write w "%STEWARD-E-NOLOGIN, your login directory ", f$trnlnm("SYS$LOGIN"), " does not exist: the job logs in there and writes its log there"
$ close w
$ st = 1
$ goto done
$have_login:
$! The log's name from the time: STEWARD_PCSI_<yyyymmddhhmmss>.LOG.
$ t = f$cvtime()
$ logname = "STEWARD_PCSI_" + f$extract(0, 4, t) + f$extract(5, 2, t) + f$extract(8, 2, t) + -
            f$extract(11, 2, t) + f$extract(14, 2, t) + f$extract(17, 2, t) + ".LOG"
$ submit 'p_job' /queue=SYS$BATCH /noprint /name=STEWARD_PCSI /log_file=SYS$LOGIN:'logname' -
      /parameters=("''p_op'","''p_prod'","''p_base'","''p_name'","''p_ver'","''p_src'","''p_dest'","''privs'")
$ st = f$integer($status)
$ open/write w 'rep'
$ write w "%%SUBMIT%% ", f$fao("!XL", st)
$ if .not. st then write w f$message(st)
$ if st then write w "%%ENTRY%% ", $entry
$ if st then write w "%%LOG%% ", logname
$ close w
$ st = 1
$ goto done
$!
$! ok: chk is "-", or 1 to 200 characters all in chkset.
$check:
$ ok = 0
$ if chk .eqs. "-" then ok = 1
$ if ok then return
$ if f$length(chk) .lt. 1 .or. f$length(chk) .gt. 200 then return
$ i = 0
$checkc:
$ if i .ge. f$length(chk) then ok = 1
$ if ok then return
$ if f$locate(f$extract(i, 1, chk), chkset) .ge. f$length(chkset) then return
$ i = i + 1
$ goto checkc
$!
$done:
$ if f$type(st) .eqs. "" then st = 20       ! SS$_BADPARAM: refused above
$ open/write w 'rep'
$ write w "%%END%% ", f$fao("!XL", st)
$ close w
$ logout/brief
