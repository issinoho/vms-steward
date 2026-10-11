// dashboard.js - the system at a glance: the landing page.
//
// The figures are vms-fastfetch's, read under your persona (GET api/v1/system).
// It refreshes every few seconds as *background* polls, which the server does not
// count as activity, so a dashboard left open still signs out when idle. CPU usage
// is the busy share between two polls, from OpenVMS's idle-tick counter.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { vmsDate, refusal } from './fmt.js';

const REFRESH_MS = 10000;
let timer = null;
let last = null;            // the previous poll, for CPU usage

export function stopDashboard() {
  clearTimeout(timer);
  timer = null;
}

const GB = 1073741824;
function size(bytes) {
  if (bytes >= 1099511627776) return `${(bytes / 1099511627776).toFixed(1)} TB`;
  if (bytes >= GB) return `${(bytes / GB).toFixed(bytes >= 100 * GB ? 0 : 1)} GB`;
  return `${Math.round(bytes / 1048576)} MB`;
}
const pct = (part, whole) => (whole > 0 ? Math.max(0, Math.min(100, (100 * part) / whole)) : 0);

function uptime(boot) {
  if (!boot) return '—';
  let s = Math.max(0, Math.floor(Date.now() / 1000) - boot);
  const d = Math.floor(s / 86400); s %= 86400;
  const hh = String(Math.floor(s / 3600)).padStart(2, '0');
  const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
  return `${d} ${d === 1 ? 'day' : 'days'} ${hh}:${mm}`;
}

// A bar of segments: [{ value, cls, label }], over total. Widths are set through the
// DOM: the CSP (style-src 'self') refuses style="..." attributes.
function bar(total, segs, title) {
  return h('div', { class: 'bar', role: 'img', 'aria-label': title },
    segs.map((s) => {
      const seg = h('span', { class: `seg ${s.cls}`, title: s.label });
      seg.style.width = `${pct(s.value, total).toFixed(2)}%`;
      return seg;
    }));
}

// The CPU gauge: a 270-degree arc in SVG, built as markup-free DOM.
function gauge(percent) {
  const ns = 'http://www.w3.org/2000/svg';
  const svg = document.createElementNS(ns, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  svg.setAttribute('class', 'gauge');
  svg.setAttribute('aria-hidden', 'true');
  const arc = (cls, frac) => {
    const p = document.createElementNS(ns, 'path');
    const r = 48, a0 = 135 * Math.PI / 180, sweep = 270 * Math.PI / 180 * frac;
    const x0 = 60 + r * Math.cos(a0), y0 = 60 + r * Math.sin(a0);
    const x1 = 60 + r * Math.cos(a0 + sweep), y1 = 60 + r * Math.sin(a0 + sweep);
    p.setAttribute('d', `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${r} ${r} 0 ${sweep > Math.PI ? 1 : 0} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`);
    p.setAttribute('class', cls);
    return p;
  };
  svg.append(arc('track', 0.9999));
  if (percent !== null && percent > 0.2) svg.append(arc(percent >= 90 ? 'fill hot' : 'fill', percent / 100));
  return svg;
}

function cpuPercent(now) {
  if (!last || now.cpu.sampled_at_ms <= last.cpu.sampled_at_ms) return null;
  const secs = (now.cpu.sampled_at_ms - last.cpu.sampled_at_ms) / 1000;
  const capacity = secs * 100 * Math.max(1, now.cpu.active);          // idle ticks available
  const idle = now.cpu.idle_ticks - last.cpu.idle_ticks;
  return Math.max(0, Math.min(100, 100 * (1 - idle / capacity)));
}

function panel(title, ...body) {
  return h('section', { class: 'panel' }, h('h3', {}, title), ...body);
}

function render(s, cpu, el) {
  const m = s.memory;
  const disks = s.disks.map((d) => {
    const used = d.total - d.free;
    const p = pct(used, d.total);
    return h('li', { class: 'disk' },
      h('div', { class: 'disk-head' },
        h('span', { class: 'mono strong' }, d.label || d.device),
        d.system_disk ? h('span', { class: 'tag' }, 'SYSTEM DISK') : null,
        h('span', { class: 'mono muted grow' }, `${d.device} ${d.logical_volume}`),
        h('span', { class: p >= 90 ? 'mono warn-text' : 'mono' }, `${p.toFixed(0)}%`)),
      bar(d.total, [{ value: used, cls: p >= 90 ? 'hot' : 'used', label: `${size(used)} used` }], `${d.label}: ${p.toFixed(0)}% used`),
      h('div', { class: 'disk-foot muted' }, `${size(d.free)} free of ${size(d.total)} · ${d.filesystem}`));
  });
  const q = s.queues, j = q.jobs;
  mount(el,
    h('section', { class: 'hero-panel' },
      h('div', { class: 'node' },
        h('span', { class: 'node-name' }, s.node),
        h('span', { class: 'node-os' }, `OpenVMS ${s.os.version} · ${s.os.arch}`),
        h('span', { class: 'muted' }, s.hardware.model, s.hardware.virtual_machine ? ' · virtual machine' : '')),
      h('dl', { class: 'uptime' },
        h('dt', {}, 'Up'), h('dd', { class: 'mono' }, uptime(s.boot_time)),
        h('dt', {}, 'Booted'), h('dd', { class: 'mono' }, s.boot_time ? vmsDate(s.boot_time, false) : '—'),
        h('dt', {}, 'Cluster'), h('dd', { class: 'mono' }, s.cluster.member
          ? `${s.cluster.nodes} nodes, ${s.cluster.votes} votes (quorum ${s.cluster.quorum})` : 'standalone'))),
    h('div', { class: 'panels' },
      panel('CPU',
        h('div', { class: 'cpu' },
          h('div', { class: 'gauge-wrap' }, gauge(cpu),
            h('span', { class: 'gauge-value' }, cpu === null ? '…' : `${cpu.toFixed(0)}%`)),
          h('dl', { class: 'facts small-facts' },
            h('dt', {}, 'CPUs'), h('dd', { class: 'mono' }, `${s.cpu.active} active of ${s.cpu.available}`),
            h('dt', {}, 'Running'), h('dd', { class: 'mono' }, String(s.cpu.load.current)),
            h('dt', {}, 'Waiting'), h('dd', { class: 'mono' }, String(s.cpu.load.computable + s.cpu.load.computable_outswapped)))),
        cpu === null ? h('p', { class: 'muted small' }, 'Measuring: usage appears after the next refresh.') : null),
      panel('Memory',
        h('p', { class: 'big' }, size(m.in_use), h('span', { class: 'muted' }, ` in use of ${size(m.total)}`)),
        bar(m.total, [{ value: m.in_use, cls: 'used', label: 'in use' }, { value: m.modified, cls: 'mod', label: 'modified' }], 'Memory'),
        h('ul', { class: 'legend' },
          h('li', {}, h('i', { class: 'used' }), `In use ${size(m.in_use)}`),
          h('li', {}, h('i', { class: 'mod' }), `Modified ${size(m.modified)}`),
          h('li', {}, h('i', {}), `Free ${size(m.free)}`)),
        h('p', { class: 'muted small' }, `Paging and swap files: ${size(s.paging.used)} used of ${size(s.paging.total)}`)),
      panel('Processes',
        h('p', { class: 'big' }, String(s.processes.count), h('span', { class: 'muted' }, ' visible to you')),
        s.processes.hidden ? h('p', { class: 'muted small' },
          `${s.processes.hidden} more that OpenVMS does not show you (GROUP or WORLD privilege would).`) : null,
        h('h4', {}, 'Interactive sessions'),
        s.processes.interactive.length
          ? h('ul', { class: 'keys' }, s.processes.interactive.map((u) =>
              h('li', {}, u.username, u.sessions > 1 ? h('span', { class: 'count' }, `×${u.sessions}`) : null)))
          : h('span', { class: 'muted' }, 'None visible')),
      panel('Queues',
        h('p', { class: 'big' }, String(q.count), h('span', { class: 'muted' }, ` queues · ${q.batch} batch, ${q.output} output`)),
        q.stopped ? h('p', { class: 'warn-text small' }, `${q.stopped} stopped`) : null,
        h('dl', { class: 'facts small-facts' },
          h('dt', {}, 'Executing'), h('dd', { class: 'mono' }, String(j.executing)),
          h('dt', {}, 'Pending'), h('dd', { class: 'mono' }, String(j.pending)),
          h('dt', {}, 'Holding'), h('dd', { class: 'mono' }, String(j.holding)),
          h('dt', {}, 'Timed'), h('dd', { class: 'mono' }, String(j.timed))))),
    h('section', { class: 'panel wide' }, h('h3', {}, 'Disks'), h('ul', { class: 'disks' }, disks)));
}

export async function dashboardView(ctx) {
  stopDashboard();
  last = null;
  const body = h('div', { class: 'dashboard' }, h('span', { class: 'muted' }, 'Reading…'));
  const stamp = h('span', { class: 'stamp muted' });

  async function poll(background) {
    try {
      const s = await api.system(background);
      if (!background) ctx.touched();
      const cpu = cpuPercent(s);
      last = s;
      render(s, cpu, body);
      stamp.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { stopDashboard(); ctx.authLost(); return; }
      if (!background) throw err;
      stamp.textContent = 'Not updated: Steward could not be reached';
    }
    schedule();
  }
  // The first refresh comes quickly, so CPU usage (which needs two readings) shows
  // within seconds; then every REFRESH_MS.
  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(() => {
      if (document.hidden) { schedule(); return; }   // no polling while the tab is hidden
      poll(true);
    }, last && last.first ? 2000 : REFRESH_MS);
    if (last) last.first = false;
  }

  try {
    await poll(false);
    if (last) { last.first = true; schedule(); }
  } catch (err) {
    return [h('h2', {}, 'Dashboard'), refusal(err)];
  }
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Dashboard'),
      h('span', { class: 'live' }, h('span', { class: 'led', 'aria-hidden': 'true' }), stamp)),
    body,
  ];
}
