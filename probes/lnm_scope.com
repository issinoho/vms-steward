$! LNM_SCOPE.COM - does SET SYMBOL/SCOPE=(NOLOCAL,NOGLOBAL) stop a global verb
$! symbol (as a viewer's LOGIN.COM could define) from taking over a command in
$! STEWARD_LNM.COM? On x86 (2026-10-13): without it, DIRECTORY ran the symbol; with
$! it, the verb. A global SHOW symbol never replaced the SHOW verb, scope or not, so
$! SHOW is no test of this.
$ directory == "write sys$output ""TAKEN OVER"""
$ write sys$output "without the scope:"
$ directory nl:
$ set symbol/scope=(nolocal,noglobal)
$ write sys$output "with it:"
$ directory nl:
$ set symbol/scope=(local,global)
$ delete/symbol/global directory
