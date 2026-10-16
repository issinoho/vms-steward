$! LIC_VIEW.COM - what may a user read of the licences? Run in batch as the user,
$! P1 the privileges to switch on first ("" for none). Prints the process's
$! privileges, then SHOW LICENSE/FULL (the loaded licences, in memory), SHOW
$! LICENSE/UNIT_REQUIREMENTS and LICENSE LIST/FULL (the database, LMF$LICENSE), each
$! followed by its $STATUS. Read-only.
$ set noon
$ if p1 .nes. "" then set process/privileges=('p1')
$ write sys$output "PRIVS|", f$getjpi("", "CURPRIV")
$ write sys$output "== SHOW LICENSE/FULL"
$ show license/full
$ write sys$output "STATUS|", $status
$ write sys$output "== SHOW LICENSE/UNIT_REQUIREMENTS"
$ show license/unit_requirements
$ write sys$output "STATUS|", $status
$ write sys$output "== LICENSE LIST/FULL"
$ license list/full
$ write sys$output "STATUS|", $status
$ exit
