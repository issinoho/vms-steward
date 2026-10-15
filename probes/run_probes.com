$! RUN_PROBES.COM - build the Phase 0 probes and run the read-only ones.
$!
$!   @RUN_PROBES [BUILD|ALL]
$!     BUILD  compile and link only
$!     ALL    (default) also run probe_crypto, probe_rights and probe_uaf
$!
$! probe_persona, probe_setprv, probe_crelnm, probe_jpi, probe_delprc, probe_acm and probe_acm_host need a username (and the
$! acm ones a password), so
$! they are run by hand; see the comment at the top of each source file.
$!
$! VSI C with 32-bit pointers, linked against SSL3$LIBCRYPTO_SHR32, as in
$! vmsguard's build_vms.com (DECISIONS D3). LINK reports undefined symbols as
$! warnings and still writes the image, so $SEVERITY is checked after each one.
$!
$ set noon
$ say = "write sys$output"
$ define/process/nolog sys$error sys$output
$ op = f$edit(p1, "UPCASE,TRIM")
$ if op .eqs. "" then op = "ALL"
$!
$ say "=== environment"
$ say "OpenVMS ", f$getsyi("VERSION"), " on ", f$getsyi("HW_NAME")
$ cc/version nl:
$ say "user ", f$edit(f$getjpi("", "USERNAME"), "TRIM")
$ ap = f$getjpi("", "AUTHPRIV")
$ say "IMPERSONATE (DETACH) authorized: ", f$locate(",DETACH,", ","+ap+",") .lt. f$length(ap)+2
$ say "SYSPRV authorized: ", f$locate(",SYSPRV,", ","+ap+",") .lt. f$length(ap)+2
$ say "SYSPRV enabled now: ", f$privilege("SYSPRV")
$ directory/nohead/notrail sys$library:SSL3$LIBCRYPTO_SHR32.EXE
$ show logical SSL3$INCLUDE
$!
$ define/process/nolog OPENSSL SSL3$INCLUDE:
$ ccq = "/STANDARD=C99/POINTER_SIZE=32/NAMES=AS_IS/WARNINGS=ENABLE=QUESTCODE"
$ failed = 0
$ probes = "probe_crypto,probe_rights,probe_uaf,probe_persona,probe_acm,probe_acm_host,probe_setprv,probe_selfuai,probe_crelnm,probe_jpi,probe_delprc,probe_hold"
$ i = 0
$build_loop:
$ p = f$element(i, ",", probes)
$ if p .eqs. "," then goto build_done
$ i = i + 1
$ say "=== build ", p
$ cc'ccq' 'p'.c
$ if .not. $status
$ then
$   say "BUILD-FAIL compile ", p
$   failed = failed + 1
$   goto build_loop
$ endif
$ if p .eqs. "probe_crypto"
$ then
$   open/write o probe_crypto.opt
$   write o "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32/SHARE"
$   close o
$   link 'p',probe_crypto.opt/options
$ else
$   link 'p'
$ endif
$ if $severity .ne. 1
$ then
$   say "BUILD-FAIL link ", p, " (severity ", $severity, ")"
$   failed = failed + 1
$ endif
$ goto build_loop
$build_done:
$ say "=== built with ", failed, " failure(s)"
$ if op .eqs. "BUILD" then exit 1
$!
$ say "=== run probe_crypto"
$ run probe_crypto
$ say "=== run probe_rights"
$ mcr sys$disk:[]probe_rights
$ say "=== run probe_uaf"
$ mcr sys$disk:[]probe_uaf 10
$ say "=== done"
$ exit 1
