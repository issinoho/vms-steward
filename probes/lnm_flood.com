$! LNM_FLOOD.COM - a D14 helper that keeps the reply mailbox full and never sends
$! %%END%% (Phase 7 review, finding S1): what a viewer's own LOGIN.COM could do.
$! Steward must stop at its deadline and delete it.
$ set noon
$ prc = f$edit(f$getjpi("", "PRCNAM"), "TRIM")
$ rep = "_MBA" + f$element(1, "_", prc - "STW") + ":"
$ open/write w 'rep'
$loop:
$ write w "  ""FLOOD"" [super] = ""X"""
$ goto loop
