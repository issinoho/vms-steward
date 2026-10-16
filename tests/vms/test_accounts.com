$! TEST_ACCOUNTS.COM - create (or remove) the two accounts the live tests and probes
$! run as, the same as on the x86 node. Run by the node's administrator, not by the
$! tests: it changes SYSUAF and the rights database.
$!
$!   @TEST_ACCOUNTS            create STEWARD_TEST and STEWARD_ADM, asking for
$!                             their passwords (not echoed)
$!   @TEST_ACCOUNTS REMOVE     remove both accounts, their UIC identifiers and their
$!                             (empty) home directories
$!
$!   STEWARD_TEST [362,1]  the unprivileged viewer: TMPMBX NETMBX, GRPPRV authorized
$!                         only (phase7b: its group's table). Full access, so batch
$!                         jobs can be submitted as it (phase8b, 9, 9b).
$!   STEWARD_ADM  [362,3]  the administrator: GROUP NETMBX SYSNAM SYSPRV TMPMBX WORLD
$!                         authorized, only TMPMBX NETMBX default (D9). Network
$!                         access only, DISCTLY.
$!
$! [362,2] is left for the service account STEWARD, which STEWARD$CONFIGURE creates.
$! The live tests also expect group 362 (phase4 creates [362,10] and [362,11];
$! phase7 and 7b use LNM$GROUP_000362). Needs SYSPRV (or SYSTEM's UIC).
$!
$ set noon
$ say = "write sys$output"
$ op = f$edit(p1, "UPCASE,TRIM")
$ if op .nes. "" .and. op .nes. "REMOVE"
$ then
$   say "TEST_ACCOUNTS: usage: @TEST_ACCOUNTS [REMOVE]"
$   exit 44
$ endif
$ saved = f$environment("DEFAULT")
$ set default SYS$SYSTEM
$ if op .eqs. "REMOVE" then goto do_remove
$!
$! Both or neither: never half a set, and never touch an existing account.
$ if f$identifier("STEWARD_TEST", "NAME_TO_NUMBER") .ne. 0 .or. -
     f$identifier("STEWARD_ADM", "NAME_TO_NUMBER") .ne. 0
$ then
$   say "TEST_ACCOUNTS: STEWARD_TEST or STEWARD_ADM already exists; nothing done"
$   goto fail
$ endif
$! The UICs as numbers: group 362 (octal) is %XF2.
$ if f$identifier(%X00F20001, "NUMBER_TO_NAME") .nes. "" .or. -
     f$identifier(%X00F20003, "NUMBER_TO_NAME") .nes. ""
$ then
$   say "TEST_ACCOUNTS: [362,1] or [362,3] is already in use; nothing done"
$   goto fail
$ endif
$!
$ acct = "STEWARD_TEST"
$ gosub ask_pw
$ if pw .eqs. "" then goto fail
$ pw_test = pw
$ acct = "STEWARD_ADM"
$ gosub ask_pw
$ if pw .eqs. "" then goto fail_scrub
$ pw_adm = pw
$ pw = ""
$!
$ mcr authorize add STEWARD_TEST /uic=[362,1] /owner="steward probe" -
      /device=SYS$SYSDEVICE /directory=[STEWARD_TEST] /password="''pw_test'" /nopwdexpired -
      /privileges=(TMPMBX,NETMBX,GRPPRV) /defprivileges=(TMPMBX,NETMBX) /flags=nodisuser
$ pw_test = ""
$ if f$identifier("STEWARD_TEST", "NAME_TO_NUMBER") .eq. 0
$ then
$   say "TEST_ACCOUNTS: AUTHORIZE ADD STEWARD_TEST failed"
$   goto fail_scrub
$ endif
$ mcr authorize add STEWARD_ADM /uic=[362,3] /owner="Steward admin test" -
      /device=SYS$SYSDEVICE /directory=[STEWARD_ADM] /password="''pw_adm'" /nopwdexpired -
      /privileges=(GROUP,NETMBX,SYSNAM,SYSPRV,TMPMBX,WORLD) /defprivileges=(TMPMBX,NETMBX) -
      /flags=(disctly,nodisuser) /noaccess /network
$ pw_adm = ""
$ if f$identifier("STEWARD_ADM", "NAME_TO_NUMBER") .eq. 0
$ then
$   say "TEST_ACCOUNTS: AUTHORIZE ADD STEWARD_ADM failed (STEWARD_TEST was created)"
$   goto fail
$ endif
$ if f$parse("SYS$SYSDEVICE:[STEWARD_TEST]") .eqs. "" then -
      create/directory/owner=[362,1] SYS$SYSDEVICE:[STEWARD_TEST]
$ if f$parse("SYS$SYSDEVICE:[STEWARD_ADM]") .eqs. "" then -
      create/directory/owner=[362,3] SYS$SYSDEVICE:[STEWARD_ADM]
$ say "TEST_ACCOUNTS: created STEWARD_TEST [362,1] and STEWARD_ADM [362,3]"
$ define/user sysuaf sys$system:sysuaf
$ mcr authorize show STEWARD_TEST/brief
$ define/user sysuaf sys$system:sysuaf
$ mcr authorize show STEWARD_ADM/brief
$ set default 'saved'
$ exit 1
$!
$do_remove:
$ n = 0
$rm_loop:
$ acct = f$element(n, ",", "STEWARD_TEST,STEWARD_ADM")
$ if acct .eqs. "," then goto rm_done
$ n = n + 1
$ if f$identifier(acct, "NAME_TO_NUMBER") .ne. 0
$ then
$   define/user sys$output nla0:
$   mcr authorize remove 'acct'          ! removes the UIC identifier too
$   if f$identifier(acct, "NAME_TO_NUMBER") .ne. 0
$   then
$     say "TEST_ACCOUNTS: AUTHORIZE REMOVE ", acct, " failed"
$   else
$     say "TEST_ACCOUNTS: removed ", acct
$   endif
$ else
$   say "TEST_ACCOUNTS: no account ", acct
$ endif
$ dirfile = "SYS$SYSDEVICE:[000000]" + acct + ".DIR;1"
$ if f$search(dirfile) .nes. ""
$ then
$   if f$search("SYS$SYSDEVICE:[''acct']*.*;*") .nes. ""
$   then
$     say "TEST_ACCOUNTS: SYS$SYSDEVICE:[", acct, "] is not empty; left in place"
$   else
$     set security/protection=(o:rwed) 'dirfile'
$     delete/nolog 'dirfile'
$     say "TEST_ACCOUNTS: removed SYS$SYSDEVICE:[", acct, "]"
$   endif
$ endif
$ goto rm_loop
$rm_done:
$ set default 'saved'
$ exit 1
$!
$! Ask twice for acct's password, without echo; pw is "" on a mismatch or a bad one.
$! At most 32 characters: UAI$C_MAX_PWD_LENGTH on IA64 (NOTES.md).
$ask_pw:
$ pw = ""
$ set terminal/noecho
$ read/end_of_file=ask_end/prompt="Password for ''acct': " sys$command pw
$ say ""
$ read/end_of_file=ask_end/prompt="Again: " sys$command pw2
$ say ""
$ set terminal/echo
$ if pw .nes. pw2
$ then
$   say "TEST_ACCOUNTS: the passwords differ"
$   pw = ""
$ endif
$ if pw .nes. "" .and. (f$length(pw) .gt. 32 .or. f$locate("""", pw) .lt. f$length(pw))
$ then
$   say "TEST_ACCOUNTS: 1 to 32 characters, and no double quote"
$   pw = ""
$ endif
$ pw2 = ""
$ return
$ask_end:
$ set terminal/echo
$ pw = ""
$ pw2 = ""
$ return
$!
$fail_scrub:
$ pw = ""
$ pw_test = ""
$ pw_adm = ""
$fail:
$ set default 'saved'
$ exit 44
