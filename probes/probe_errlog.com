$! probe_errlog.com - Phase 14 probe, read-only: where the error log is, who may read
$! it, what ANALYZE/ERROR_LOG (and its ELV form) gives with and without privilege, and
$! the device error counts anyone may read. Run with tools/vms.sh <node> run.
$ set noon
$ say = "write sys$output"
$ say "== logicals"
$ show logical SYS$ERRORLOG
$ show logical/full ERRLOG*
$ say "== files"
$ directory/size=all/date=(created,modified)/protection/owner SYS$ERRORLOG:*.*;*
$ say "== ERRFMT process"
$ show system/process=ERRFMT
$ say "== my privileges (authorized)"
$ say f$extract(0, 200, f$getjpi("", "AUTHPRIV"))
$ say "== device error counts (unprivileged)"
$ set process/privilege=(noall,tmpmbx,netmbx)
$ show error
$ ctx = ""
$dloop:
$ d = f$device("*", "DISK", , ctx)
$ if d .eqs. "" then goto ddone
$ if f$getdvi(d, "EXISTS") then say d, " ERRCNT=", f$getdvi(d, "ERRCNT"), " MNT=", f$getdvi(d, "MNT")
$ goto dloop
$ddone:
$ say "== ANALYZE/ERROR_LOG unprivileged"
$ analyze/error_log/since=-7-/brief/output=sys$scratch:pe_nopriv.lis
$ say "status ", $status
$ if f$search("sys$scratch:pe_nopriv.lis") .nes. "" then type/page=save=0 sys$scratch:pe_nopriv.lis
$ say "== ANALYZE/ERROR_LOG/ELV unprivileged"
$ analyze/error_log/elv translate/since=-7-/output=sys$scratch:pe_elv_nopriv.lis
$ say "status ", $status
$ say "== with privileges (SYSPRV)"
$ set process/privilege=sysprv
$ say "current: ", f$extract(0, 200, f$getjpi("", "CURPRIV"))
$ analyze/error_log/since=-7-/brief/output=sys$scratch:pe_brief.lis
$ say "brief status ", $status
$ analyze/error_log/since=-7-/output=sys$scratch:pe_full.lis
$ say "full status ", $status
$ analyze/error_log/elv translate/since=-7-/output=sys$scratch:pe_elv.lis
$ say "elv status ", $status
$ analyze/error_log/elv translate/since=-7-/summary/output=sys$scratch:pe_elvsum.lis
$ say "elv summary status ", $status
$ directory/size sys$scratch:pe_*.lis
$ set process/privilege=nosysprv
$ say "== END"
