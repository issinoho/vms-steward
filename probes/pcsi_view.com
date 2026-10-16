$! PCSI_VIEW.COM - what may a user read of the installed products? Run in batch as
$! the user, P1 the privileges to switch on first ("" for none). Prints the process's
$! privileges, then PRODUCT SHOW PRODUCT/FULL, PRODUCT SHOW HISTORY/FULL and PRODUCT
$! SHOW PRODUCT with /OUTPUT= to a file in SYS$LOGIN (then typed and deleted), each
$! followed by its $STATUS. Read-only.
$ set noon
$ if p1 .nes. "" then set process/privileges=('p1')
$ write sys$output "PRIVS|", f$getjpi("", "CURPRIV")
$ write sys$output "== PRODUCT SHOW PRODUCT/FULL"
$ product show product/full
$ write sys$output "STATUS|", $status
$ write sys$output "== PRODUCT SHOW HISTORY/FULL"
$ product show history/full
$ write sys$output "STATUS|", $status
$ write sys$output "== PRODUCT SHOW PRODUCT/OUTPUT="
$ product show product/output=sys$login:p12_out.txt
$ write sys$output "STATUS|", $status
$ if f$search("sys$login:p12_out.txt") .nes. "" then type sys$login:p12_out.txt
$ if f$search("sys$login:p12_out.txt") .nes. "" then delete/nolog sys$login:p12_out.txt;*
$ exit
