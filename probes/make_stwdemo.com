$! make_stwdemo.com - build ISSINOHO <base> STWDEMO V1.0, a PCSI kit of one text file,
$! for testing Phase 12b (D26): install and remove it through Steward. Writes only in
$! the work directory: [.STWDEMO.MAT] (its material), [.STWDEMO.KIT] (the kit).
$! Installing it (with /DESTINATION in the work directory) adds an entry to the PCSI
$! database, and removing it takes the entry away: the user allowed that on x86
$! (PHASE12.md, 2026-10-17).
$!
$! Usage: @[.PROBES]MAKE_STWDEMO      (from the work directory)
$ set noon
$ say = "write sys$output"
$ here = f$parse(f$environment("PROCEDURE"),,,"DEVICE") + f$parse(f$environment("PROCEDURE"),,,"DIRECTORY")
$ top = here - ".PROBES]" - ".probes]"
$ top = top - "]"
$ base = "X86VMS"
$ if f$getsyi("ARCH_NAME") .eqs. "IA64" then base = "I64VMS"
$ mat = top + ".STWDEMO.MAT]"
$ kdir = top + ".STWDEMO.KIT]"
$ desc = top + ".STWDEMO]"
$ if f$search(top + "]STWDEMO.DIR") .eqs. "" then create/directory 'desc'
$ if f$search(desc + "MAT.DIR") .eqs. "" then create/directory 'mat'
$ if f$search(desc + "KIT.DIR") .eqs. "" then create/directory 'kdir'
$ if f$search(kdir + "*.PCSI") .nes. "" then delete/nolog 'kdir'*.PCSI;*
$ open/write w 'mat'README.TXT
$ write w "STWDEMO: a kit of one file, for testing Steward's install and remove (Phase 12b)."
$ close w
$ open/write w 'desc'STWDEMO.PCSI$DESC
$ write w "product ISSINOHO ", base, " STWDEMO V1.0 full ;"
$ write w "    directory [STWDEMO] ;"
$ write w "    file [STWDEMO]README.TXT ;"
$ write w "end product ;"
$ close w
$ product package STWDEMO /producer=ISSINOHO /base_system='base' /version=V1.0 -
      /source='desc'STWDEMO.PCSI$DESC /material='mat' /destination='kdir' -
      /format=sequential /options=noconfirm /log
$ say "MAKE_STWDEMO: status ", $status
$ directory/size 'kdir'
