// rates.js - monitoring's arithmetic (Phase 13, D21): rates from two readings of
// OpenVMS's counters (GET api/v1/monitor). Pure: no DOM and no fetch, so it is tested
// on its own (tests/ui/rates_unit.mjs).
//
// The counters run from boot. The I/O and paging counters are longwords and wrap at
// 2^32; a wrap goes from the top half to the bottom, anything else that goes back is a
// reboot (or a counter reset), and gives no rate. The CPU mode counters are ticks
// summed over the CPUs, 100 a second a CPU; interrupt time reads negative on the x86
// VM (NOTES.md) and is shown as 0, as MONITOR shows it.

const WRAP = 2 ** 32;
const HALF = 2 ** 31;

export const MODES = ['interrupt', 'mp_synch', 'kernel', 'executive', 'supervisor', 'user'];
export const COUNTERS = ['page_faults', 'page_read_io', 'page_write_io', 'inswaps', 'direct_io', 'buffered_io',
  'mailbox_reads', 'mailbox_writes'];

// The change in a 32-bit counter, or null if it went back other than by wrapping.
export function delta32(prev, cur) {
  if (cur >= prev) return cur - prev;
  if (prev >= HALF && cur < HALF) return cur + WRAP - prev;
  return null;
}

const perSec = (d, dt) => (d === null ? null : d / dt);
const clampPct = (x) => Math.max(0, Math.min(100, x));

// The sample between two readings: rates a second, CPU modes as a share of all CPUs,
// and the processes seen in both by their counters' changes. null when no rate can be
// had: no earlier reading, time not moving forward, or a reboot between the two.
export function sample(prev, cur) {
  if (!prev || !cur) return null;
  const dt = (cur.sampled_at_ms - prev.sampled_at_ms) / 1000;
  if (!(dt > 0)) return null;
  if (cur.modes.idle < prev.modes.idle || cur.modes.kernel < prev.modes.kernel) return null;   // rebooted
  const capacity = 100 * (cur.cpus || 1) * dt;   // ticks the CPUs had between the two
  const cpu = {};
  for (const m of MODES) cpu[m] = clampPct((100 * Math.max(0, cur.modes[m] - prev.modes[m])) / capacity);
  cpu.idle = clampPct((100 * Math.max(0, cur.modes.idle - prev.modes.idle)) / capacity);
  cpu.busy = clampPct(MODES.reduce((t, m) => t + cpu[m], 0));
  const rates = {};
  for (const k of COUNTERS) rates[k] = perSec(delta32(prev.counters[k], cur.counters[k]), dt);
  const before = new Map(prev.disks.map((d) => [d.device, d.operations]));
  const disks = cur.disks.map((d) => ({
    device: d.device,
    rate: before.has(d.device) ? perSec(delta32(before.get(d.device), d.operations), dt) : null,
  }));
  return {
    t: cur.sampled_at_ms,
    dt,
    cpu,
    states: { ...cur.states },
    processes: cur.processes,
    memory: { ...cur.memory },
    rates,
    disks,
    busiest: busiest(prev.visible, cur.visible, dt),
  };
}

// Each process in both readings (by PID): its CPU as a share of one CPU (as SHOW
// PROCESS/CONTINUOUS and MONITOR PROCESSES/TOPCPU put it) and its I/O and faults a
// second. One that came or went between the two has no rate and is left out.
export function busiest(prevList, curList, dt) {
  const before = new Map((prevList || []).map((p) => [p.pid, p]));
  const out = [];
  for (const p of curList || []) {
    const q = before.get(p.pid);
    if (!q || p.cpu_ms < q.cpu_ms) continue;   // new, or a PID reused
    const dio = delta32(q.direct_io, p.direct_io);
    const bio = delta32(q.buffered_io, p.buffered_io);
    const pf = delta32(q.page_faults, p.page_faults);
    out.push({
      pid: p.pid, name: p.name, username: p.username, state: p.state,
      cpu: (100 * (p.cpu_ms - q.cpu_ms)) / (1000 * dt),
      direct_io: perSec(dio, dt), buffered_io: perSec(bio, dt), page_faults: perSec(pf, dt),
      io: ((dio || 0) + (bio || 0)) / dt,
    });
  }
  return out;
}

// Samples from the recording's readings, oldest first: one between each two. One that
// spans a gap (the recorder stopped, readings missing, a reboot) is left out, and the
// next is marked, so the charts break there rather than draw a long average.
export function historySamples(readings, stepS) {
  const out = [];
  let gap = false;
  for (let i = 1; i < readings.length; i++) {
    const s = sample(readings[i - 1], readings[i]);
    if (!s || s.dt > 1.5 * stepS) { gap = true; continue; }
    s.gap = gap;
    gap = false;
    out.push(s);
  }
  return out;
}

// The top n by a key, leaving out those with nothing to show.
export function top(list, key, n) {
  return list.filter((p) => (p[key] || 0) > 0).sort((a, b) => b[key] - a[key] || (a.pid < b.pid ? -1 : 1)).slice(0, n);
}

// The history: samples within the window (ms) of the newest, oldest first.
export function keep(history, s, windowMs) {
  const out = s ? [...history, s] : [...history];
  const newest = out.length ? out[out.length - 1].t : 0;
  return out.filter((x) => x.t >= newest - windowMs);
}
