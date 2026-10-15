$! PROBE_HOLD.COM - run probe_hold detached (RUN/DETACH of LOGINOUT with this as input):
$!   P1 = the directory holding PROBE_HOLD.EXE, P2 = username, P3 = seconds.
$ set default 'p1'
$ ph = "$" + p1 + "probe_hold"
$ ph 'p2' 'p3'
