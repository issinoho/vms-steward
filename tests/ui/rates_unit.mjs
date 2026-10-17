// rates_unit.mjs - monitoring's arithmetic (www/js/rates.js), on its own: no DOM, no
// server. Counters that wrap, a reboot, processes that come and go, the CPU share and
// the negative interrupt count the x86 VM reports (NOTES.md).
const { delta32, sample, busiest, top, keep } = await import(process.env.STEWARD_UI_JS + '/rates.js');

let failed = 0;
const say = (ok, what, extra = '') => { if (!ok) failed++; console.log(ok ? 'ok  ' : 'FAIL', what, ok ? '' : extra); };
const near = (a, b, eps = 1e-9) => a != null && Math.abs(a - b) < eps;

function reading(t, o = {}) {
  return {
    sampled_at_ms: t, cpus: 2,
    modes: { interrupt: 0, mp_synch: 0, kernel: 0, executive: 0, supervisor: 0, user: 0, idle: 0, ...(o.modes || {}) },
    states: { CUR: 1, COM: 0, LEF: 10, HIB: 5 },
    processes: 16,
    memory: { total: 100, free: 60, modified: 5 },
    counters: { page_faults: 0, page_read_io: 0, page_write_io: 0, inswaps: 0, direct_io: 0, buffered_io: 0,
      mailbox_reads: 0, mailbox_writes: 0, ...(o.counters || {}) },
    disks: o.disks || [{ device: 'DKA0:', operations: 0 }],
    visible: o.visible || [],
  };
}

say(delta32(10, 15) === 5 && delta32(15, 15) === 0, 'a counter that went up');
say(delta32(4294967290, 4) === 10, 'a 32-bit counter that wrapped', delta32(4294967290, 4));
say(delta32(1000, 10) === null, 'one that went back (a reboot): no change');

{
  const a = reading(0, { modes: { interrupt: -100, kernel: 1000, user: 2000, idle: 10000 } });
  // 10 s on 2 CPUs: 2000 ticks. Kernel 400 (20%), user 200 (10%), idle 1400 (70%); interrupt falls by 26.
  const b = reading(10000, { modes: { interrupt: -126, kernel: 1400, user: 2200, idle: 11400 } });
  const s = sample(a, b);
  say(s && near(s.dt, 10) && near(s.cpu.kernel, 20) && near(s.cpu.user, 10) && near(s.cpu.idle, 70),
    'CPU modes as a share of all CPUs', s && s.cpu);
  say(s && s.cpu.interrupt === 0 && near(s.cpu.busy, 30), 'interrupt below zero shown as 0; busy the sum of the modes', s && s.cpu);
}
{
  const a = reading(0, { counters: { direct_io: 4294967000, buffered_io: 100 }, disks: [{ device: 'DKA0:', operations: 50 }] });
  const b = reading(2000, { counters: { direct_io: 704, buffered_io: 300 },
    disks: [{ device: 'DKA0:', operations: 70 }, { device: 'DKA100:', operations: 5 }] });
  const s = sample(a, b);
  say(s && near(s.rates.direct_io, 500) && near(s.rates.buffered_io, 100), 'rates a second, across a wrap', s && s.rates);
  say(s && near(s.disks[0].rate, 10) && s.disks[1].rate === null, 'disk operations a second; a disk new since the last reading has none', s && s.disks);
}
{
  const a = reading(0, { modes: { idle: 5000, kernel: 900 } });
  const b = reading(5000, { modes: { idle: 100, kernel: 10 } });
  say(sample(a, b) === null, 'a reboot between two readings: no sample');
  say(sample(null, b) === null && sample(b, b) === null, 'no earlier reading, or no time between: none');
}
{
  const before = [
    { pid: 'A', name: 'BUSY', username: 'U', state: 'COM', cpu_ms: 1000, direct_io: 10, buffered_io: 10, page_faults: 0 },
    { pid: 'B', name: 'IDLE', username: 'U', state: 'HIB', cpu_ms: 50, direct_io: 0, buffered_io: 0, page_faults: 0 },
    { pid: 'C', name: 'GONE', username: 'U', state: 'LEF', cpu_ms: 0, direct_io: 0, buffered_io: 0, page_faults: 0 },
  ];
  const after = [
    { pid: 'A', name: 'BUSY', username: 'U', state: 'CUR', cpu_ms: 3000, direct_io: 30, buffered_io: 50, page_faults: 4 },
    { pid: 'B', name: 'IDLE', username: 'U', state: 'HIB', cpu_ms: 50, direct_io: 0, buffered_io: 0, page_faults: 0 },
    { pid: 'D', name: 'NEW', username: 'U', state: 'COM', cpu_ms: 900, direct_io: 0, buffered_io: 0, page_faults: 0 },
  ];
  const list = busiest(before, after, 4);
  const a = list.find((p) => p.pid === 'A');
  say(list.length === 2 && !list.find((p) => p.pid === 'D' || p.pid === 'C'), 'processes in both readings only: one new, one gone, left out');
  say(a && near(a.cpu, 50) && near(a.direct_io, 5) && near(a.buffered_io, 10) && near(a.io, 15) && near(a.page_faults, 1),
    'a process: CPU as a share of one CPU, I/O and faults a second', a);
  say(top(list, 'cpu', 10).map((p) => p.pid).join() === 'A', 'the busiest by CPU, nothing idle among them');
}
{
  let h = [];
  for (let t = 0; t <= 40 * 60000; t += 60000) h = keep(h, { t }, 30 * 60000);
  say(h.length === 31 && h[0].t === 10 * 60000 && h[30].t === 40 * 60000, 'the history: the last 30 minutes', h.length);
}
process.exit(failed ? 1 : 0);
