$! STEWARD_PCSI_JOB.COM - install or remove a product, as the user this batch job runs
$! as (Phase 12b, D26). Submitted to SYS$BATCH by STEWARD_PCSI.COM, under the viewer's
$! own name, logging to SYS$LOGIN:STEWARD_PCSI_<time>.LOG, which Steward's page reads.
$!
$!   P1 INSTALL or REMOVE   P2 producer   P3 base   P4 name   P5 version ("-")
$!   P6 source directory ("-")   P7 destination directory ("-")
$!   P8 the privileges switched on in Steward ("-" for none)
$!
$! Unattended: /OPTIONS=NOCONFIRM, and the kit's questions answered from the product
$! database for an upgrade (/CONFIGURATION=CURRENT) or by the producer's defaults for
$! a new product (PRODUCER). PRODUCT reads nothing from this procedure: SYS$INPUT is
$! the null device for it, so a question it still asks ends the operation instead of
$! taking the next line of this file as its answer. The last line of the log is
$! "%%PCSI-END%% <status>" (hexadecimal).
$!
$! The user's LOGIN.COM has run first: none of its symbols reaches this level after
$! the next line. No symbol here is named after a verb it uses (CLAUDE.md).
$ set symbol/scope=(nolocal,noglobal)
$ set noon
$ say = "write sys$output"
$ st = 20                              ! SS$_BADPARAM until checked
$ p_op = p1
$ p_prod = p2
$ p_base = p3
$ p_name = p4
$ p_ver = p5
$ p_src = p6
$ p_dest = p7
$ privs = p8
$ if p_op .nes. "INSTALL" .and. p_op .nes. "REMOVE" then goto finish
$ okd = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-.:[]"
$ okw = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$_-."
$ okp = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_,"
$ chkset = okw
$ chk = p_prod
$ gosub check
$ if .not. ok then goto finish
$ chk = p_base
$ gosub check
$ if .not. ok then goto finish
$ chk = p_name
$ gosub check
$ if .not. ok then goto finish
$ chk = p_ver
$ gosub check
$ if .not. ok then goto finish
$ chkset = okd
$ chk = p_src
$ gosub check
$ if .not. ok then goto finish
$ chk = p_dest
$ gosub check
$ if .not. ok then goto finish
$ chkset = okp
$ chk = privs
$ gosub check
$ if .not. ok then goto finish
$ if p_prod .eqs. "-" .or. p_base .eqs. "-" .or. p_name .eqs. "-" then goto finish
$ if p_op .eqs. "INSTALL" .and. (p_src .eqs. "-" .or. p_ver .eqs. "-") then goto finish
$!
$ say "Steward: ", p_op, " ", p_prod, " ", p_base, " ", p_name, " ", p_ver, " (", f$time(), ")"
$ if privs .nes. "-" then set process/privilege=('privs')
$ say "Privileges switched on: ", f$extract(0, 200, f$getjpi("", "CURPRIV"))
$ if p_op .eqs. "REMOVE" then goto do_remove
$!
$! An upgrade keeps the answers given when it was installed; a new product takes the
$! producer's. Installed if PRODUCT SHOW lists it.
$ conf = "PRODUCER"
$ pipe product show product 'p_name' /producer='p_prod' /base_system='p_base' | -
       search/nooutput sys$pipe " 0 items found"
$ if $severity .ne. 1 then conf = "CURRENT"
$ say "Configuration: ", conf
$ dq = ""
$ if p_dest .nes. "-" then dq = "/destination=" + p_dest
$ define/user sys$input nla0:
$ product install 'p_name' /producer='p_prod' /base_system='p_base' /version='p_ver' -
      /source='p_src' /configuration='conf' /options=noconfirm /log 'dq'
$ st = f$integer($status)
$ goto finish
$!
$do_remove:
$ define/user sys$input nla0:
$ product remove 'p_name' /producer='p_prod' /base_system='p_base' /options=noconfirm /log
$ st = f$integer($status)
$ goto finish
$!
$! ok: chk is "-", or 1 to 255 characters all in chkset.
$check:
$ ok = 0
$ if chk .eqs. "-" then ok = 1
$ if ok then return
$ if f$length(chk) .lt. 1 .or. f$length(chk) .gt. 255 then return
$ i = 0
$checkc:
$ if i .ge. f$length(chk) then ok = 1
$ if ok then return
$ if f$locate(f$extract(i, 1, chk), chkset) .ge. f$length(chkset) then return
$ i = i + 1
$ goto checkc
$!
$finish:
$ say "%%PCSI-END%% ", f$fao("!XL", st)
$ exit 1
