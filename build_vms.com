$! BUILD_VMS.COM - build Steward on OpenVMS (x86-64), VSI C with 32-bit pointers.
$!
$!   @BUILD_VMS            build [.BUILD]STEWARD.EXE and [.BUILD]TEST_CORE.EXE
$!   @BUILD_VMS TEST       ... and run TEST_CORE (the core unit tests, natively)
$!   @BUILD_VMS CLEAN      delete [.BUILD] first (MMS-style flag tracking does not
$!                         exist here: rebuild from CLEAN after changing headers)
$!
$! The only VMS build file (vmsguard's lesson: three build files drift, and on VMS
$! they fail quietly). Linked against SSL3$LIBCRYPTO_SHR32, which matches 32-bit
$! pointers; the 64-bit image would link and then crash (DECISIONS D3).
$!
$! Strict: a compile that ends in a warning or worse stops the build, and so does
$! any LINK that is not clean. LINK reports undefined symbols as *warnings* and
$! still writes an image that crashes when it reaches them, and ON ERROR does not
$! catch a warning, hence $SEVERITY after every step.
$!
$ set noon
$ say = "write sys$output"
$ mode = f$edit(p1, "UPCASE,TRIM")
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ set default 'here'
$ if mode .eqs. "CLEAN" .and. f$search("[]BUILD.DIR") .nes. ""
$ then
$   delete/nolog [.build]*.*;*
$   set security/protection=(o:rwed) []build.dir
$   delete/nolog []build.dir;
$ endif
$ if f$search("[]BUILD.DIR") .eqs. "" then create/directory [.build]
$!
$ if f$trnlnm("SSL3$INCLUDE") .eqs. ""
$ then
$   say "BUILD-FAIL: SSL3$INCLUDE is not defined (VSI OpenSSL 3 kit)"
$   exit 44
$ endif
$! The OpenSSL headers are chosen by the logical name OPENSSL alone (vmsguard).
$ define/process/nolog OPENSSL SSL3$INCLUDE:
$ open/write o [.build]ssl.opt
$ write o "SYS$LIBRARY:SSL3$LIBCRYPTO_SHR32/SHARE"
$ close o
$!
$! As vmsguard's build_vms.com: under /STANDARD=C99 only ANSI names get the DECC$
$! prefix, so the socket calls would link as undefined symbols without
$! ALL_ENTRIES (seen 2026-10-10: 11 undefined, socket to inet_addr).
$! _SOCKADDR_LEN selects the BSD 4.4 sockaddr layout.
$ ccq = "/STANDARD=C99/POINTER_SIZE=32/PREFIX_LIBRARY_ENTRIES=ALL_ENTRIES" + -
        "/DEFINE=(_SOCKADDR_LEN)/NOLIST" + -
        "/INCLUDE_DIRECTORY=([.src.core],[.src.svc],[.src.plat])"
$ failed = 0
$ sources = "[.src.core]st_buf,[.src.core]st_fcgi,[.src.core]st_json,[.src.core]st_http," + -
            "[.src.core]st_route,[.src.svc]st_app,[.src.svc]svc_session," + -
            "[.src.svc]svc_users,[.src.svc]svc_idents," + -
            "[.src.plat]st_crypto_openssl,[.src.plat.vms]st_plat_vms," + -
            "[.src.plat.stub]st_plat_stub,[.src.main]steward_main,[.tests.unit]test_core," + -
            "[.tests.vms]api_probe"
$ i = 0
$cc_loop:
$ s = f$element(i, ",", sources)
$ if s .eqs. "," then goto cc_done
$ i = i + 1
$ name = f$parse(s,,,"NAME","SYNTAX_ONLY")
$ cc'ccq' 's'.c /object=[.build]'name'.obj
$ sev = $severity
$ if sev .ne. 1 .and. sev .ne. 3
$ then
$   say "BUILD-FAIL compile ", s, " (severity ", sev, ")"
$   failed = failed + 1
$ endif
$ goto cc_loop
$cc_done:
$ if failed .gt. 0
$ then
$   say "BUILD-FAIL: ", failed, " compile(s) failed"
$   exit 44
$ endif
$!
$ core = "[.build]st_buf,[.build]st_fcgi,[.build]st_json,[.build]st_http,[.build]st_route," + -
         "[.build]st_app,[.build]svc_session,[.build]svc_users,[.build]svc_idents," + -
         "[.build]st_crypto_openssl"
$ link/executable=[.build]steward.exe 'core',[.build]st_plat_vms,[.build]steward_main,[.build]ssl.opt/options
$ if $severity .ne. 1
$ then
$   say "BUILD-FAIL link STEWARD.EXE (severity ", $severity, ")"
$   exit 44
$ endif
$ link/executable=[.build]test_core.exe 'core',[.build]st_plat_stub,[.build]test_core,[.build]ssl.opt/options
$ if $severity .ne. 1
$ then
$   say "BUILD-FAIL link TEST_CORE.EXE (severity ", $severity, ")"
$   exit 44
$ endif
$! API_PROBE: one request as a named user through the real platform, for checking
$! results against AUTHORIZE (tests/vms/api_probe.c). A test tool, not part of the kit.
$ link/executable=[.build]api_probe.exe 'core',[.build]st_plat_vms,[.build]api_probe,[.build]ssl.opt/options
$ if $severity .ne. 1
$ then
$   say "BUILD-FAIL link API_PROBE.EXE (severity ", $severity, ")"
$   exit 44
$ endif
$ say "BUILD-OK [.BUILD]STEWARD.EXE, [.BUILD]TEST_CORE.EXE, [.BUILD]API_PROBE.EXE"
$!
$ if mode .nes. "TEST" then exit 1
$ say "=== TEST_CORE"
$ run [.build]test_core
$ if .not. $status
$ then
$   say "TEST-FAIL"
$   exit 44
$ endif
$ say "TEST-OK"
$ exit 1
