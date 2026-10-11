$! STEWARD$CONFIGURE.COM - set up Steward (run once, as SYSTEM; safe to run again)
$!
$! Usage:  @STEWARD$ROOT:[COM]STEWARD$CONFIGURE [account] [uic] [data-dir] [port]
$!                                              [web-account] [proxies] [autostart]
$!   account      service account (default STEWARD)
$!   uic          its UIC, e.g. [362,2]; needed only if the account is new
$!   data-dir     sessions, audit log, settings, lighttpd rules
$!                (default SYS$SYSDEVICE:[STEWARD_DATA])
$!   port         the port lighttpd serves Steward on (default 8443)
$!   web-account  lighttpd's account, which must read the gateway secret
$!                (default: VMSLIGHTTPD's, else LIGHTTPD)
$!   proxies      reverse proxies to trust (D7), e.g. 192.0.2.10; "" for none
$!   autostart    YES: STEWARD$STARTUP starts the pool at boot (default NO)
$! Missing values are asked for when run interactively.
$!
$! What it does (README.VMS):
$!  - the account: batch access only, RESTRICTED, DISCTLY, an unknown password;
$!    privileges IMPERSONATE, TMPMBX, NETMBX by default, and SYSPRV authorized but
$!    not default: Steward switches it on only around $PERSONA_CREATE (DECISIONS D2).
$!    An existing account keeps its UIC and password; its privileges are set as above
$!    and its default directory becomes the data directory.
$!  - the data directory, owned by the account: LOGIN.COM (required for a
$!    RESTRICTED account), [.RUN] (sessions, audit log, settings, pool logs; private
$!    to the account), [.CONF] (lighttpd rules)
$!  - a gateway secret (64 hex characters from OpenSSL's generator, STEWARD -g),
$!    shared by the pool (STEWARD_SETTINGS.COM) and lighttpd (STEWARD_GATEWAY.CONF,
$!    readable by lighttpd's account only). Existing settings and their secret are
$!    kept.
$!  - [.CONF]STEWARD.CONF: a lighttpd server block for the port, to include from
$!    LIGHTTPD.CONF (rewritten each time)
$!  - SYS$MANAGER:STEWARD$CONFIG.COM, the site settings (rewritten each time)
$!
$ set noon
$ set process/parse_style=extended
$ say = "write sys$output"
$ interactive = f$mode() .eqs. "INTERACTIVE"
$ if f$trnlnm("STEWARD$ROOT") .eqs. ""
$ then
$   say "STEWARD$CONFIGURE: STEWARD$ROOT is not defined (@SYS$STARTUP:STEWARD$STARTUP)"
$   exit 44
$ endif
$ if .not. f$privilege("SYSPRV,CMKRNL")
$ then
$   say "STEWARD$CONFIGURE: needs SYSPRV and CMKRNL (run it as SYSTEM)"
$   exit 36
$ endif
$!
$ webdefault = "LIGHTTPD"
$ if f$search("SYS$MANAGER:VMSLIGHTTPD$CONFIG.COM") .nes. ""
$ then
$   @SYS$MANAGER:VMSLIGHTTPD$CONFIG.COM
$   webdefault = vmslighttpd_account
$ endif
$ call ask account "Service account" "STEWARD" 'p1'
$ call ask datadir "Data directory" "SYS$SYSDEVICE:[STEWARD_DATA]" 'p3'
$ call ask port "Port lighttpd serves Steward on" "8443" 'p4'
$ call ask webacct "lighttpd's account" 'webdefault' 'p5'
$ call ask proxies "Reverse proxies to trust (addresses, comma-separated; empty for none)" "" "''p6'"
$ call ask autostart "Start the pool at boot (YES/NO)" "NO" 'p7'
$ account = f$edit(account, "UPCASE")
$ webacct = f$edit(webacct, "UPCASE")
$ autostart = f$edit(autostart, "UPCASE")
$ proxies = f$edit(proxies, "COLLAPSE")
$ count = 2
$ base = 19300
$ if f$identifier(webacct, "NAME_TO_NUMBER") .eq. 0
$ then
$   say "STEWARD$CONFIGURE: no account ", webacct, " for lighttpd (install and configure vms-lighttpd first)"
$   exit 44
$ endif
$!
$! --- the account ------------------------------------------------------------
$ access = "/NOINTERACTIVE/NONETWORK/NOLOCAL/NODIALUP/NOREMOTE/BATCH"
$ privs = "/PRIVILEGES=(IMPERSONATE,TMPMBX,NETMBX,SYSPRV)/DEFPRIVILEGES=(IMPERSONATE,TMPMBX,NETMBX)"
$ datadev = f$parse(datadir,,,"DEVICE")
$ datadirpart = f$parse(datadir,,,"DIRECTORY")
$ steward = "$STEWARD$ROOT:[BIN]STEWARD.EXE"
$ saved = f$environment("DEFAULT")
$ set default SYS$SYSTEM
$ if f$identifier(account, "NAME_TO_NUMBER") .eq. 0
$ then
$   call ask uic "UIC for the new account, e.g. [362,2]" "" 'p2'
$   if uic .eqs. ""
$   then
$     say "STEWARD$CONFIGURE: a UIC is needed for a new account"
$     set default 'saved'
$     exit 44
$   endif
$   gosub new_secret                      ! a draw of its own, never the gateway secret
$   password = f$extract(0, 32, secret)   ! never used: the account logs in only by batch
$   define/user sys$output nla0:
$   mcr authorize add 'account' /uic='uic' /password='password' /pwdexpired -
        /flags=(restricted,disctly,nodisuser) /device='datadev' /directory='datadirpart' -
        'access' 'privs' /owner="Steward service"
$   password = ""
$   secret = ""
$   if f$identifier(account, "NAME_TO_NUMBER") .eq. 0
$   then
$     say "STEWARD$CONFIGURE: AUTHORIZE ADD ", account, " failed"
$     set default 'saved'
$     exit 44
$   endif
$   say "STEWARD$CONFIGURE: created account ", account, " ", uic
$ else
$   define/user sys$output nla0:
$   mcr authorize modify 'account' 'privs' /device='datadev' /directory='datadirpart'
$   say "STEWARD$CONFIGURE: account ", account, " exists; privileges set to IMPERSONATE, TMPMBX, NETMBX (default)"
$   say "                   and SYSPRV (authorized only); its default directory is now ", datadir
$   say "                   (the pool logs in there, and needs the LOGIN.COM written below)"
$ endif
$ set default 'saved'
$ uicnum = f$identifier(account, "NAME_TO_NUMBER")
$ uicstr = f$fao("!%U", uicnum)
$ webuic = f$fao("!%U", f$identifier(webacct, "NAME_TO_NUMBER"))
$!
$! --- the data directory -----------------------------------------------------
$ top = f$parse(datadir,,,"DEVICE","NO_CONCEAL") + f$parse(datadir,,,"DIRECTORY","NO_CONCEAL")
$ j = f$locate("][", top)
$ if j .lt. f$length(top) then top = f$extract(0, j, top) + "." + f$extract(j + 2, 999, top)
$ top = top - ".000000" - "]"
$! The top directory: E (look up by name, no listing) for everyone, so lighttpd's
$! account can reach [.CONF]; [.RUN] below it is the account's alone.
$ if f$parse(top + "]") .eqs. "" then create/directory/owner='uicstr'/protection=(S:RWE,O:RWE,G:E,W:E) 'top']
$ if f$parse(top + ".RUN]") .eqs. "" then create/directory/owner='uicstr'/protection=(S:RWED,O:RWED,G,W) 'top'.RUN]
$ if f$parse(top + ".CONF]") .eqs. "" then create/directory/owner='uicstr'/protection=(S:RWE,O:RWE,G:RE,W:RE) 'top'.CONF]
$ run = top + ".RUN]"
$ conf = top + ".CONF]"
$! LOGIN.COM: readable, not writable, by the account
$ copy/nolog STEWARD$ROOT:[COM]LOGIN.COM 'top']LOGIN.COM
$ set security/owner='uicstr'/protection=(S:RWED,O:RE,G,W) 'top']LOGIN.COM;*   ! S:D, so PURGE can remove old versions
$ purge/nolog 'top']LOGIN.COM
$!
$! UNIX form of a directory, for lighttpd (/DEVICE/DIR/SUBDIR)
$ call unixdir udata 'top']
$ call unixdir uwww STEWARD$ROOT:[WWW]
$!
$! Stream_LF FDL for the lighttpd files
$ open/write fdl 'conf'STMLF.FDL
$ write fdl "RECORD"
$ write fdl "  FORMAT STREAM_LF"
$ close fdl
$!
$! --- settings and the gateway secret ----------------------------------------
$ settings = run + "STEWARD_SETTINGS.COM"
$ secret = ""
$ if f$search(settings) .nes. "" then gosub old_secret
$ if secret .nes. ""
$ then
$   say "STEWARD$CONFIGURE: kept ", settings, " and its gateway secret"
$   goto have_secret
$ endif
$ gosub new_secret
$ if f$length(secret) .ne. 64
$ then
$   say "STEWARD$CONFIGURE: could not make a gateway secret (STEWARD -g)"
$   exit 44
$ endif
$ if f$search(settings) .nes. ""
$ then   ! settings without a secret: add one, keep the rest
$   open/append s 'settings'
$   write s "$! Added by STEWARD$CONFIGURE ", f$time(), "; shared with lighttpd (", conf, "STEWARD_GATEWAY.CONF)"
$   write s "$ define/process/nolog STEWARD_GATEWAY_SECRET """, secret, """"
$   close s
$   say "STEWARD$CONFIGURE: added a gateway secret to ", settings
$   goto have_secret
$ endif
$ open/write s 'settings'
$ write s "$! STEWARD_SETTINGS.COM - site settings for the Steward pool, written by"
$ write s "$! STEWARD$CONFIGURE ", f$time(), ". Each pool process runs it; restart"
$ write s "$! the pool after a change (STEWARD$CONTROL RESTART). Private to the account."
$ write s "$!"
$ write s "$! Reverse proxies whose X-Forwarded-* headers are believed (DECISIONS D7)."
$ if proxies .eqs. ""
$ then
$   write s "$! define/process/nolog STEWARD_TRUSTED_PROXIES ""192.0.2.10"""
$ else
$   write s "$ define/process/nolog STEWARD_TRUSTED_PROXIES """, proxies, """"
$ endif
$ write s "$! Shared with lighttpd (", conf, "STEWARD_GATEWAY.CONF): change both together."
$ write s "$ define/process/nolog STEWARD_GATEWAY_SECRET """, secret, """"
$ write s "$! Sessions end after this many seconds without an API call, and after"
$ write s "$! this many in any case."
$ write s "$ define/process/nolog STEWARD_IDLE_SECS ""900"""
$ write s "$ define/process/nolog STEWARD_ABSOLUTE_SECS ""28800"""
$ close s
$ say "STEWARD$CONFIGURE: wrote ", settings
$have_secret:
$ set security/owner='uicstr'/protection=(S:RWED,O:RWED,G,W) 'settings';0
$ purge/nolog 'settings'
$!
$! lighttpd's half of the secret: readable by lighttpd's account only
$ gw = conf + "STEWARD_GATEWAY.CONF"
$ open/write g 'conf'GATEWAY.TMP
$ write g "# STEWARD_GATEWAY.CONF - written by STEWARD$CONFIGURE; readable by lighttpd only."
$ write g "# lighttpd sends this with every API request, overwriting any value a client sent,"
$ write g "# and Steward refuses requests without it (README.VMS)."
$ write g "setenv.set-request-header = ( ""X-Steward-Gateway"" => """, secret, """ )"
$ close g
$ secret = ""
$ convert/fdl='conf'STMLF.FDL 'conf'GATEWAY.TMP 'gw'
$ delete/nolog 'conf'GATEWAY.TMP;*
$ set security/owner='webuic'/protection=(S:RWED,O:RE,G,W) 'gw';*   ! S:D, so PURGE can remove old versions
$ purge/nolog 'gw'
$!
$! The server block
$ open/write c 'conf'STEWARD.TMP
$ write c "# STEWARD.CONF - Steward on port ", port, ", written by STEWARD$CONFIGURE ", f$time()
$ write c "# Include it from LIGHTTPD.CONF (after server.modules, which must list mod_fastcgi"
$ write c "# and mod_setenv):"
$ write c "#     include """, udata, "/conf/steward.conf"""
$ write c "# Rewritten by STEWARD$CONFIGURE; changes here are lost."
$ write c "$SERVER[""socket""] == "":", port, """ {"
$ write c "    server.document-root = """, uwww, """"
$ write c "    index-file.names = ( ""index.html"" )"
$ write c "    # the API: to the pool, with the gateway secret"
$ write c "    $HTTP[""url""] =~ ""^/api/"" {"
$ write c "        include """, udata, "/conf/steward_gateway.conf"""
$ write c "    }"
$ write c "    fastcgi.server = ( ""/api/"" => ("
$ n = 0
$fcgi_loop:
$ sep = ","
$ if n .eq. count - 1 then sep = ""
$ write c "        ( ""host"" => ""127.0.0.1"", ""port"" => ", base + n, ", ""check-local"" => ""disable"" )", sep
$ n = n + 1
$ if n .lt. count then goto fcgi_loop
$ write c "    ) )"
$ write c "    # the page: its own scripts, styles and images only; never framed"
$ write c "    $HTTP[""url""] !~ ""^/api/"" {"
$ write c "        setenv.add-response-header = ("
$ write c "            ""Content-Security-Policy"" => ""default-src 'self'; img-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"","
$ write c "            ""X-Frame-Options"" => ""DENY"","
$ write c "            ""Referrer-Policy"" => ""no-referrer"","
$ write c "            ""X-Content-Type-Options"" => ""nosniff"""
$ write c "        )"
$ write c "    }"
$ write c "    # HTTPS here, if no proxy in front ends TLS: Steward's cookie is Secure, so"
$ write c "    # browsers must reach it over HTTPS one way or the other (README.VMS)."
$ write c "    #ssl.engine  = ""enable"""
$ write c "    #ssl.pemfile = """, udata, "/conf/server.pem"""
$ write c "}"
$ close c
$ convert/fdl='conf'STMLF.FDL 'conf'STEWARD.TMP 'conf'STEWARD.CONF
$ delete/nolog 'conf'STEWARD.TMP;*
$ purge/nolog 'conf'STEWARD.CONF
$ set security/owner='uicstr'/protection=(S:RWED,O:RWED,G:RE,W:RE) 'conf'STEWARD.CONF;0
$ delete/nolog 'conf'STMLF.FDL;*   ! only needed while writing these
$ say "STEWARD$CONFIGURE: wrote ", conf, "STEWARD.CONF and STEWARD_GATEWAY.CONF"
$!
$! --- site settings ----------------------------------------------------------
$ node = f$edit(f$getsyi("NODENAME"), "UPCASE")
$ open/write s SYS$MANAGER:STEWARD$CONFIG.COM
$ write s "$! STEWARD$CONFIG.COM - Steward site settings, written by STEWARD$CONFIGURE"
$ write s "$! ", f$time(), "; run STEWARD$CONFIGURE again to change them"
$ write s "$ steward_account   == """, account, """"
$ write s "$ steward_data      == """, top, "]"""
$ write s "$ steward_port      == """, port, """"
$ write s "$ steward_count     == """, count, """"
$ write s "$ steward_base      == """, base, """"
$ write s "$ steward_autostart == """, autostart, """"
$ write s "$ steward_node      == """, node, """   ! start only on this cluster member"
$ close s
$ set security/protection=(S:RWED,O:RWED,G:RE,W:RE) SYS$MANAGER:STEWARD$CONFIG.COM
$ say "STEWARD$CONFIGURE: wrote SYS$MANAGER:STEWARD$CONFIG.COM"
$ say ""
$ say "Next:"
$ say "  1. Add to lighttpd's LIGHTTPD.CONF, then restart lighttpd:"
$ say "         include """, udata, "/conf/steward.conf"""
$ say "  2. HTTPS: Steward's cookie is Secure. Either put a TLS proxy in front (nginx"
$ say "     proxy manager: list its address as a trusted proxy) or uncomment ssl.* in"
$ say "     STEWARD.CONF with a PEM readable by ", webacct, " only."
$ say "  3. Start:   @STEWARD$ROOT:[COM]STEWARD$CONTROL START"
$ say "     Check:   @STEWARD$ROOT:[COM]STEWARD$CONTROL STATUS"
$ say "  4. At boot: add @SYS$STARTUP:STEWARD$STARTUP to SYS$MANAGER:SYSTARTUP_VMS.COM"
$ say "     At shutdown: add @SYS$STARTUP:STEWARD$SHUTDOWN to SYS$MANAGER:SYSHUTDWN.COM"
$ exit 1
$!
$! new_secret: secret = 64 hex characters from STEWARD -g
$new_secret:
$ tmp = "SYS$SCRATCH:STEWARD_SECRET_''f$getjpi("","PID")'.TMP"
$ define/user sys$output 'tmp'
$ steward "-g"
$ secret = ""
$ if f$search(tmp) .nes. ""
$ then
$   open/read t 'tmp'
$   read/end=ns_done t secret
$ns_done:
$   close t
$   delete/nolog 'tmp';*
$ endif
$ secret = f$edit(secret, "TRIM")
$ return
$!
$! old_secret: secret = STEWARD_GATEWAY_SECRET from the existing settings
$old_secret:
$ open/read t 'settings'
$os_loop:
$ read/end=os_done t line
$ if f$locate("STEWARD_GATEWAY_SECRET", line) .ge. f$length(line) then goto os_loop
$ if f$extract(0, 2, f$edit(line, "TRIM")) .eqs. "$!" then goto os_loop
$ secret = f$element(1, """", line)
$ if secret .eqs. """" then secret = ""
$os_done:
$ close t
$ return
$!
$! ask <symbol> <prompt> <default> [<value given>]
$ask: subroutine
$ v = p4
$ if v .eqs. "" .and. interactive
$ then
$   read/prompt="''p2' [''p3']: " sys$command v
$ endif
$ if v .eqs. "" then v = p3
$ 'p1' == v
$ exit 1
$ endsubroutine
$!
$! unixdir <symbol> <directory>: /DEVICE/DIR/SUBDIR, rooted directories joined
$unixdir: subroutine
$ d = f$parse(p2,,,"DEVICE","NO_CONCEAL") - ":"
$ r = f$parse(p2,,,"DIRECTORY","NO_CONCEAL")
$ j = f$locate(".][", r)
$ if j .lt. f$length(r) then r = f$extract(0, j, r) + "." + f$extract(j + 3, 999, r)
$ r = f$extract(1, f$length(r) - 2, r) - "000000." - ".000000"
$ u = "/" + d + "/" + r
$ud_loop:
$ j = f$locate(".", u)
$ if j .lt. f$length(u)
$ then
$   u = f$extract(0, j, u) + "/" + f$extract(j + 1, 999, u)
$   goto ud_loop
$ endif
$ 'p1' == u
$ exit 1
$ endsubroutine
