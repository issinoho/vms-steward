$! LNM_FAKEEND.COM - a D14 helper that answers "%%END%% 1" and stays, as the viewer's
$! LOGIN.COM could (Phase 11 review). Steward must still delete it: only OpenVMS's
$! termination message for the helper's PID says it is gone.
$ prc = f$edit(f$getjpi("", "PRCNAM"), "TRIM")
$ rep = "_MBA" + f$string(f$integer("%X" + f$extract(7, 4, prc))) + ":"
$ open/write w 'rep'
$ write w "%%END%% 1"
$ close w
$ wait 00:02:00
$ logout/brief
