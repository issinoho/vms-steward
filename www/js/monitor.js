// monitor.js - monitoring (Phase 13, D21, D22): MONITOR's classes over time.
//
// Live, the page polls GET api/v1/monitor (every 5 s by default; 2, 10 or 30 to
// choose) as background requests, which do not count as activity, so a page left open
// still signs out when idle (as the dashboard). Each reading is raw counters; rates.js
// turns two into a sample, and the last 30 minutes of samples are kept here, in the
// page: leaving it drops them. Polls pause while the tab is hidden, and the charts show
// the gap.
//
// The longer ranges come from the recording on the node (GET api/v1/monitor/history,
// D22): readings a whole number of the recorder's intervals apart, the same raw
// counters, so rates.js gives the exact average between each two. Fetched again each
// minute. Processes are not recorded: the busiest tables are live only.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';
import { sample, keep, top, historySamples, MODES } from './rates.js';

const WINDOW_MS = 30 * 60 * 1000;
const INTERVALS = [2, 5, 10, 30];
const FIRST_MS = 1000;   // the second reading comes quickly, so rates show at once
const KEY = 'steward.monitor.interval';
const RANGE_KEY = 'steward.monitor.range';
// Live, or minutes of the recording. 300 points each: every 2, 5 and 34 minutes at the
// recorder's 60 s.
const RANGES = [['live', 'Live, 30 minutes'], ['360', 'Last 6 hours'], ['1440', 'Last 24 hours'], ['10080', 'Last 7 days']];
const POINTS = 300;
const HISTORY_REFRESH_MS = 60000;

let timer = null;
let generation = 0;      // a poll that returns after the page was left is dropped

export function stopMonitor() {
  clearTimeout(timer);
  timer = null;
  generation++;
}

function savedInterval() {
  try {
    const v = Number(localStorage.getItem(KEY));
    return INTERVALS.includes(v) ? v : 5;
  } catch { return 5; }
}
function saveInterval(v) {
  try { localStorage.setItem(KEY, String(v)); } catch { /* a convenience only */ }
}
function savedRange() {
  try {
    const v = localStorage.getItem(RANGE_KEY);
    return RANGES.some(([k]) => k === v) ? v : 'live';
  } catch { return 'live'; }
}
function saveRange(v) {
  try { localStorage.setItem(RANGE_KEY, v); } catch { /* a convenience only */ }
}

// ---- formatting

const pct = (x) => (x == null ? '—' : `${x.toFixed(1)}%`);
function rate(x) {
  if (x == null) return '—';
  if (x < 10) return x.toFixed(1);
  return Math.round(x).toLocaleString('en-GB');
}
const MB = 1048576;
const size = (b) => (b >= 1024 * MB ? `${(b / (1024 * MB)).toFixed(1)} GB` : `${Math.round(b / MB)} MB`);
function ago(ms) {
  const m = Math.max(1, Math.round(ms / 60000));
  if (m < 120) return `${m} min ago`;
  const hrs = Math.round(m / 60);
  return hrs < 48 ? `${hrs} h ago` : `${Math.round(hrs / 24)} days ago`;
}
function every(secs) {
  if (secs < 120) return `${secs} s`;
  return secs % 60 ? `${(secs / 60).toFixed(1)} min` : `${secs / 60} min`;
}
const clock = (ms) => new Date(ms).toLocaleString('en-GB', { weekday: 'short', hour: '2-digit', minute: '2-digit' });
const MODE_LABEL = { interrupt: 'Interrupt', mp_synch: 'MP synch', kernel: 'Kernel', executive: 'Executive',
  supervisor: 'Supervisor', user: 'User' };

// ---- charts: SVG built as DOM, colours from CSS classes (the CSP refuses style="")

const NS = 'http://www.w3.org/2000/svg';
const W = 600;
const H = 120;

function svgEl(tag, attrs) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

// series: [{ label, values, shown }], one value per sample (null: none); samples give
// the times and the gaps. stacked: areas on one another; else lines. max: the top of
// the scale, or null to fit the data.
function chart({ title, series, samples, stacked, max, unit, fmt }) {
  const n = samples.length;
  const t1 = n ? samples[n - 1].t : 0;
  const t0 = n ? Math.min(samples[0].t, t1 - 60000) : 0;
  const span = Math.max(1, t1 - t0);
  const x = (t) => ((t - t0) / span) * W;
  const tops = series.map(() => new Array(n).fill(null));
  const bases = series.map(() => new Array(n).fill(null));
  for (let i = 0; i < n; i++) {
    let acc = 0;
    series.forEach((s, k) => {
      const v = s.values[i];
      if (v == null) return;
      bases[k][i] = stacked ? acc : 0;
      acc = stacked ? acc + v : v;
      tops[k][i] = acc;
    });
  }
  let peak = 0;
  for (const col of tops) for (const v of col) if (v != null && v > peak) peak = v;
  const top = max != null ? max : Math.max(peak * 1.15, 1);
  const y = (v) => H - (Math.min(v, top) / top) * H;

  // The runs of samples without a gap or a missing value: each is drawn on its own.
  function runs(k) {
    const out = [];
    let cur = [];
    for (let i = 0; i < n; i++) {
      if (tops[k][i] == null || (samples[i].gap && cur.length)) { if (cur.length) out.push(cur); cur = []; }
      if (tops[k][i] != null) cur.push(i);
    }
    if (cur.length) out.push(cur);
    return out;
  }

  const svg = svgEl('svg', { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: 'none', class: 'chart-plot', 'aria-hidden': 'true' });
  for (let g = 1; g < 4; g++) svg.append(svgEl('line', { x1: 0, x2: W, y1: (H * g) / 4, y2: (H * g) / 4, class: 'grid' }));
  series.forEach((s, k) => {
    for (const r of runs(k)) {
      const pts = r.map((i) => `${x(samples[i].t).toFixed(1)},${y(tops[k][i]).toFixed(1)}`);
      if (r.length === 1) pts.push(`${(x(samples[r[0]].t) + 2).toFixed(1)},${y(tops[k][r[0]]).toFixed(1)}`);
      if (stacked) {
        const back = r.slice().reverse().map((i) => `${x(samples[i].t).toFixed(1)},${y(bases[k][i]).toFixed(1)}`);
        if (r.length === 1) back.unshift(`${(x(samples[r[0]].t) + 2).toFixed(1)},${y(bases[k][r[0]]).toFixed(1)}`);
        svg.append(svgEl('polygon', { points: [...pts, ...back].join(' '), class: `area s${k % 6}` }));
      }
      svg.append(svgEl('polyline', { points: pts.join(' '), class: `line s${k % 6}` }));
    }
  });

  const last = n ? n - 1 : -1;
  const legend = h('ul', { class: 'chart-legend' }, series.map((s, k) => h('li', {},
    h('span', { class: `key s${k % 6}`, 'aria-hidden': 'true' }), s.label, ' ',
    h('span', { class: 'mono' }, last >= 0 ? fmt(s.values[last]) : '—'))));
  return h('figure', { class: 'chart' },
    h('figcaption', {}, h('span', { class: 'chart-title' }, title), legend),
    h('div', { class: 'chart-frame' },
      h('span', { class: 'chart-max mono muted' }, `${fmt(top)}${unit ? ` ${unit}` : ''}`),
      svg),
    h('div', { class: 'chart-axis muted small' }, h('span', {}, ago(Date.now() - t0)), h('span', {}, Date.now() - t1 < 90000 ? 'now' : ago(Date.now() - t1))));
}

// ---- the panels

function cpuChart(samples) {
  return chart({
    title: 'CPU, all CPUs',
    series: MODES.map((m) => ({ label: MODE_LABEL[m], values: samples.map((s) => s.cpu[m]) })),
    samples, stacked: true, max: 100, unit: '', fmt: pct,
  });
}

function statesChart(samples) {
  const pick = (s, ...keys) => keys.reduce((t, k) => t + (s.states[k] || 0), 0);
  const other = (s) => Object.values(s.states).reduce((t, v) => t + v, 0) - pick(s, 'COM', 'COMO', 'LEF', 'LEFO', 'HIB', 'HIBO', 'CUR');
  return chart({
    title: 'Process states',
    series: [
      { label: 'Current', values: samples.map((s) => pick(s, 'CUR')) },
      { label: 'Computable', values: samples.map((s) => pick(s, 'COM', 'COMO')) },
      { label: 'LEF', values: samples.map((s) => pick(s, 'LEF', 'LEFO')) },
      { label: 'HIB', values: samples.map((s) => pick(s, 'HIB', 'HIBO')) },
      { label: 'Other', values: samples.map(other) },
    ],
    samples, stacked: true, max: null, unit: 'processes', fmt: (v) => (v == null ? '—' : String(Math.round(v))),
  });
}

function memoryChart(samples) {
  const share = (s, b) => (s.memory.total ? (100 * b) / s.memory.total : null);
  const last = samples[samples.length - 1];
  return h('div', {},
    chart({
      title: 'Memory',
      series: [
        { label: 'In use', values: samples.map((s) => share(s, s.memory.total - s.memory.free - s.memory.modified)) },
        { label: 'Modified', values: samples.map((s) => share(s, s.memory.modified)) },
        { label: 'Free', values: samples.map((s) => share(s, s.memory.free)) },
      ],
      samples, stacked: true, max: 100, unit: '', fmt: pct,
    }),
    last ? h('p', { class: 'muted small' }, `${size(last.memory.free)} free of ${size(last.memory.total)}`) : null);
}

function ratesChart(title, list, samples) {
  return chart({
    title,
    series: list.map(([label, f]) => ({ label, values: samples.map(f) })),
    samples, stacked: false, max: null, unit: '/s', fmt: rate,
  });
}

const sum = (a, b) => (a == null || b == null ? null : a + b);

function disksChart(samples) {
  const last = samples[samples.length - 1];
  const devices = last ? last.disks.map((d) => d.device) : [];
  return ratesChart('Disk operations', devices.map((dev) => [dev, (s) => {
    const d = s.disks.find((x) => x.device === dev);
    return d ? d.rate : null;
  }]), samples);
}

function busiestTable(title, list, key) {
  const rows = top(list, key, 10);
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid busiest' },
    h('caption', {}, title),
    h('thead', {}, h('tr', {}, ['Process', 'User', 'State', 'CPU', 'Direct I/O', 'Buffered I/O', 'Faults']
      .map((c, i) => h('th', { class: i >= 3 ? 'num' : null }, c)))),
    h('tbody', {}, rows.length ? rows.map((p) => h('tr', {},
      h('td', {}, h('a', { href: `#/processes/${p.pid}`, class: 'mono' }, p.name)),
      h('td', { class: 'mono' }, p.username),
      h('td', { class: 'mono' }, p.state),
      h('td', { class: 'mono num' }, pct(p.cpu)),
      h('td', { class: 'mono num' }, rate(p.direct_io)),
      h('td', { class: 'mono num' }, rate(p.buffered_io)),
      h('td', { class: 'mono num' }, rate(p.page_faults))))
      : h('tr', {}, h('td', { colspan: 7, class: 'muted' }, 'Nothing busy among the processes you may see')))));
}

// view: { range: 'live', intervalS } or { range, hist } (the history response).
function render(body, samples, latest, view) {
  const live = view.range === 'live';
  if (!live && !view.hist.recording) {
    mount(body, h('p', { class: 'muted' }, 'Nothing is recorded on this node: the recorder is off or has not started (STEWARD_RECORD_SECS in the pool\'s settings). Live monitoring works without it.'));
    return;
  }
  if (!samples.length) {
    mount(body, h('p', { class: 'muted' }, live ? 'Reading… rates need two readings.'
      : 'The recording has nothing for this range yet: the recorder writes a reading each interval.'));
    return;
  }
  const s = samples[samples.length - 1];
  let footer;
  if (live) {
    footer = `The last ${Math.round(WINDOW_MS / 60000)} minutes, kept in this page while it is open, a reading every ${view.intervalS} s.`;
  } else {
    const hh = view.hist;
    const stale = Date.now() - hh.updated_ms > 3 * hh.interval_secs * 1000;
    footer = `Recorded on the node, a reading every ${every(hh.interval_secs)}, kept for ${Math.round(hh.kept_secs / 86400)} days; shown every ${every(hh.step_secs)}, each point the average since the one before.` +
      (stale ? ` The recorder has not written since ${clock(hh.updated_ms)}.` : '');
  }
  mount(body,
    h('div', { class: 'panels monitor' },
      h('section', { class: 'panel wide' }, cpuChart(samples),
        h('p', { class: 'muted small' }, `${pct(s.cpu.busy)} busy across ${latest.cpus} CPU${latest.cpus === 1 ? '' : 's'}${live ? '' : ' in the latest interval shown'}. Interrupt time is shown as 0 where OpenVMS reports it below zero, as MONITOR does.`)),
      h('section', { class: 'panel' }, statesChart(samples)),
      h('section', { class: 'panel' }, memoryChart(samples)),
      h('section', { class: 'panel' }, ratesChart('Paging', [
        ['Faults', (x) => x.rates.page_faults], ['Read I/O', (x) => x.rates.page_read_io],
        ['Write I/O', (x) => x.rates.page_write_io], ['Inswaps', (x) => x.rates.inswaps]], samples)),
      h('section', { class: 'panel' }, ratesChart('I/O', [
        ['Direct', (x) => x.rates.direct_io], ['Buffered', (x) => x.rates.buffered_io],
        ['Mailbox', (x) => sum(x.rates.mailbox_reads, x.rates.mailbox_writes)]], samples)),
      h('section', { class: 'panel wide' }, disksChart(samples)),
      live
        ? h('section', { class: 'panel wide' },
          h('h3', {}, `Busiest processes, over the last ${Math.round(s.dt)} s`),
          h('div', { class: 'busiest-pair' }, busiestTable('By CPU', s.busiest, 'cpu'), busiestTable('By I/O', s.busiest, 'io')),
          h('p', { class: 'muted small' }, `${latest.visible.length} of the ${latest.processes} processes on the system are visible to you${latest.truncated ? ' (more than Steward lists)' : ''}. CPU is a share of one CPU.`))
        : h('p', { class: 'muted small wide' }, 'Processes are not recorded (what you may see of one that has ended can no longer be asked of OpenVMS): the busiest processes are in Live.')),
    h('p', { class: 'muted small' }, footer));
}

export async function monitorView(ctx) {
  stopMonitor();
  const gen = generation;
  let intervalS = savedInterval();
  let range = savedRange();
  let last = null;
  let samples = [];
  const body = h('div', {}, h('p', { class: 'muted' }, 'Reading…'));
  const stamp = h('span', { class: 'stamp muted' });

  async function pollLive(background) {
    const r = await api.monitor(background);
    if (gen !== generation || range !== 'live') return false;
    if (!background) ctx.touched();
    const s = sample(last, r);
    if (s) {
      s.gap = s.dt > 3 * intervalS + 1;
      samples = keep(samples, s, WINDOW_MS);
    } else if (last) {
      samples = [];   // a reboot, or time went back: start again
    }
    last = r;
    render(body, samples, r, { range, intervalS });
    return true;
  }
  async function pollHistory(background) {
    const want = range;
    const r = await api.monitorHistory(Number(want), POINTS, background);
    if (gen !== generation || range !== want) return false;
    if (!background) ctx.touched();
    const readings = r.readings || [];
    render(body, r.recording ? historySamples(readings, r.step_secs) : [], readings[readings.length - 1], { range, hist: r });
    return true;
  }
  async function poll(background) {
    let shown = false;
    try {
      shown = await (range === 'live' ? pollLive(background) : pollHistory(background));
      if (!shown) return;
      stamp.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      if (gen !== generation) return;
      if (err instanceof ApiError && err.status === 401) { stopMonitor(); ctx.authLost(); return; }
      if (!background) throw err;
      stamp.textContent = 'Not updated: Steward could not be reached';
    }
    if (range !== 'live') schedule(HISTORY_REFRESH_MS);
    else schedule(samples.length ? intervalS * 1000 : FIRST_MS);
  }
  function schedule(ms) {
    clearTimeout(timer);
    if (gen !== generation) return;
    timer = setTimeout(() => {
      if (document.hidden) { schedule(range === 'live' ? intervalS * 1000 : HISTORY_REFRESH_MS); return; }   // no polling while the tab is hidden
      poll(true);
    }, ms);
  }

  const select = h('select', { 'aria-label': 'Reading interval', hidden: range !== 'live', onchange: (ev) => {
    intervalS = Number(ev.target.value);
    saveInterval(intervalS);
    schedule(intervalS * 1000);
  } }, INTERVALS.map((v) => h('option', { value: String(v), selected: v === intervalS }, `every ${v} s`)));
  const rangeSelect = h('select', { 'aria-label': 'Range', onchange: (ev) => {
    range = ev.target.value;
    saveRange(range);
    select.hidden = range !== 'live';
    clearTimeout(timer);
    last = null;      // live starts again from its first reading
    samples = [];
    mount(body, h('p', { class: 'muted' }, 'Reading…'));
    poll(true);
  } }, RANGES.map(([k, label]) => h('option', { value: k, selected: k === range }, label)));

  try {
    await poll(false);
  } catch (err) {
    return [h('h2', {}, 'Monitoring'), refusal(err)];
  }
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Monitoring'),
      h('span', { class: 'live' }, rangeSelect, select, h('span', { class: 'led', 'aria-hidden': 'true' }), stamp)),
    h('p', { class: 'muted' }, 'CPU, processes, memory, paging and I/O as MONITOR shows them, from the counters OpenVMS keeps. Anyone may read them; processes are those you may see.'),
    body,
  ];
}
