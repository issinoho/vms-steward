// processes.js - processes, read-only (Phase 8, D16).
//
// The list as SHOW SYSTEM shows it to you, and one process as SHOW PROCESS/ALL. It
// runs as you, so OpenVMS decides what you see: your own processes, your group's
// with GROUP switched on, everyone's with WORLD. The process serving your request is
// never listed: under your identity it would show as one of yours.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { vmsDate, keycaps, refusal } from './fmt.js';

const remembered = { filter: '' };   // for the way back
const procHref = (pid) => `#/processes/${pid}`;

// CPU time as SHOW SYSTEM prints it: 0 00:01:02.34 (days hours:minutes:seconds).
function cpu(ms) {
  const cs = Math.floor(ms / 10);
  const p2 = (n) => String(n).padStart(2, '0');
  const s = Math.floor(cs / 100);
  return `${Math.floor(s / 86400)} ${p2(Math.floor(s / 3600) % 24)}:${p2(Math.floor(s / 60) % 60)}:${p2(s % 60)}.${p2(cs % 100)}`;
}

// The image's name without its device, directory and version.
function imageName(spec) {
  if (!spec) return '';
  const name = spec.slice(Math.max(spec.lastIndexOf(']'), spec.lastIndexOf('>'), spec.lastIndexOf(':')) + 1);
  return name.replace(/;\d*$/, '');
}

const HINT = 'OpenVMS shows you your own processes; with GROUP switched on (My account), your UIC group\'s; with WORLD, everyone\'s.';

export async function processesView(ctx) {
  const slot = h('div');
  const input = h('input', { type: 'search', value: remembered.filter, maxlength: 31, spellcheck: 'false',
    autocapitalize: 'characters', 'aria-label': 'Filter', placeholder: '*' });
  let first = true;

  async function load() {
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.processes({ filter: remembered.filter });
      ctx.touched();
      const rows = r.processes.map((p) => h('tr', {},
        h('td', {}, h('a', { href: procHref(p.pid), class: 'mono' }, p.pid)),
        h('td', { class: 'mono' }, p.name),
        h('td', { class: 'mono' }, p.username),
        h('td', {}, h('span', { class: 'tag' }, p.state)),
        h('td', { class: 'num' }, String(p.priority)),
        h('td', {}, p.kind),
        h('td', { class: 'mono num' }, cpu(p.cpu_ms)),
        h('td', { class: 'mono' }, imageName(p.image) || h('span', { class: 'muted' }, '—'))));
      mount(slot,
        h('div', { class: 'tablewrap' }, h('table', { class: 'grid processes' },
          h('thead', {}, h('tr', {}, ['PID', 'Process name', 'Username', 'State', 'Pri', 'Kind', 'CPU', 'Image'].map((x) => h('th', {}, x)))),
          h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 8, class: 'muted' }, 'No process you may see matches'))))),
        h('p', { class: 'muted small' }, `${r.processes.length} ${r.processes.length === 1 ? 'process' : 'processes'}${r.truncated ? ' (cut short: narrow the filter)' : ''}. ${HINT}`));
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        if (first) throw err;
        ctx.authLost();
        return;
      }
      mount(slot, refusal(err));
    } finally {
      first = false;
    }
  }

  await load();
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Processes'),
      h('button', { type: 'button', onclick: () => load().catch(() => {}) }, 'Refresh')),
    h('p', { class: 'muted' }, 'The processes OpenVMS lets you see, as SHOW SYSTEM lists them. Filter by process name or username; * and % are wildcards.'),
    h('form', { class: 'cmdline', role: 'search',
      onsubmit: (ev) => { ev.preventDefault(); remembered.filter = input.value.trim(); load().catch(() => {}); } },
      h('span', { class: 'cmd' }, '$ show system /process='), input,
      h('button', { type: 'submit' }, 'Show')),
    slot,
  ];
}

const QUOTAS = [['astlm', 'ASTlm'], ['biolm', 'BIOlm'], ['diolm', 'DIOlm'], ['fillm', 'FILlm'], ['prclm', 'PRClm'],
  ['tqelm', 'TQElm'], ['enqlm', 'ENQlm'], ['bytlm', 'BYTlm'], ['pgflquota', 'Pgflquota']];

export async function processView(ctx, pid) {
  let p;
  try {
    p = await api.process(pid);
    ctx.touched();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    return [h('p', {}, h('a', { href: '#/processes' }, '← Processes')), h('h2', { class: 'mono' }, pid),
      refusal(err, err instanceof ApiError && err.status === 403 ? HINT : null)];
  }
  const link = (x) => (x ? h('a', { href: procHref(x), class: 'mono' }, x) : h('span', { class: 'muted' }, '—'));
  const current = new Set(p.current_privileges);
  return [
    h('p', {}, h('a', { href: '#/processes' }, '← Processes')),
    h('div', { class: 'titlebar' }, h('h2', { class: 'mono' }, `${p.name}`),
      h('button', { type: 'button', onclick: () => ctx.refresh() }, 'Refresh')),
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'PID'), h('dd', { class: 'mono' }, p.pid),
      h('dt', {}, 'Username'), h('dd', { class: 'mono' }, p.username),
      h('dt', {}, 'UIC'), h('dd', { class: 'mono' }, p.uic),
      h('dt', {}, 'State'), h('dd', {}, h('span', { class: 'tag' }, p.state)),
      h('dt', {}, 'Priority'), h('dd', {}, `${p.priority} (base ${p.base_priority})`),
      h('dt', {}, 'Kind'), h('dd', {}, p.kind),
      h('dt', {}, 'Terminal'), h('dd', { class: 'mono' }, p.terminal || '—'),
      h('dt', {}, 'Image'), h('dd', { class: 'mono' }, p.image || '—'),
      h('dt', {}, 'Logged in'), h('dd', {}, vmsDate(p.login)),
      h('dt', {}, 'CPU'), h('dd', { class: 'mono' }, cpu(p.cpu_ms)),
      h('dt', {}, 'I/O'), h('dd', {}, `${p.direct_io} direct, ${p.buffered_io} buffered`),
      h('dt', {}, 'Page faults'), h('dd', {}, String(p.page_faults)),
      h('dt', {}, 'Working set'), h('dd', {}, `${p.working_set_pages} pages in use; size ${p.working_set_size} pagelets`),
      h('dt', {}, 'Owner'), h('dd', {}, link(p.owner)),
      h('dt', {}, 'Master'), h('dd', {}, link(p.master === p.pid ? null : p.master)),
      h('dt', {}, 'Subprocesses'), h('dd', {}, String(p.subprocesses)))),
    h('h3', {}, 'Privileges'),
    h('p', { class: 'muted small' }, 'Authorized; the ones switched on are marked.'),
    keycaps(p.authorized_privileges, 'None', current),
    h('h3', {}, 'Rights'),
    keycaps(p.rights),
    h('h3', {}, 'Quotas'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'grid' },
      h('thead', {}, h('tr', {}, ['Quota', 'Limit', 'Left', 'In use'].map((x) => h('th', {}, x)))),
      h('tbody', {}, QUOTAS.map(([k, label]) => {
        const q = p.quotas[k];
        return h('tr', {}, h('td', {}, label), h('td', { class: 'num' }, String(q.limit)),
          h('td', { class: 'num' }, String(q.left)), h('td', { class: 'num' }, String(Math.max(0, q.limit - q.left))));
      })))),
  ];
}
