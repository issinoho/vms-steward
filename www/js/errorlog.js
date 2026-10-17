// errorlog.js - the error log, read-only (Phase 14, D23).
//
// What OpenVMS records about the hardware and itself: each device's error count (open
// to anyone), the events in ERRLOG.SYS translated by ELV (run in a short-lived process
// that is you, as for logical names), CLUE's summary of each crash, and OPCOM's log.
// The last three need SYSPRV (or the SYSTEM group) as OpenVMS sets them; a refusal is
// shown, with what would let you read them. ELV reports a file you may not read as
// "not found" (NOTES.md).

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';

const RANGES = [['7', 'Last 7 days'], ['30', 'Last 30 days'], ['365', 'Last year'], ['0', 'Everything']];
const CLASS_LABEL = { BUGCHECKS: 'Bugchecks', CONTROL_ENTRIES: 'Control entries', VOLUME_CHANGES: 'Volume changes' };
const OPCOM_PAGE = 200;

const when = (iso) => (iso || '').replace('T', ' ');
const plural = (n, one, many) => `${n} ${n === 1 ? one : many || `${one}s`}`;

// Why OpenVMS refused, and what would let you read it.
function denied(err, me, what) {
  if (!(err instanceof ApiError) || err.status !== 403) return refusal(err);
  const can = me.authorized_privileges.includes('SYSPRV');
  const on = me.current_privileges.includes('SYSPRV');
  return refusal(err, on
    ? `OpenVMS refused ${what} even with SYSPRV switched on.`
    : can
      ? h('span', {}, `${what[0].toUpperCase()}${what.slice(1)} needs SYSPRV. You hold it: switch it on under `, h('a', { href: '#/account' }, 'My account'), '.')
      : `${what[0].toUpperCase()}${what.slice(1)} needs SYSPRV (or the SYSTEM group), which your account does not have.`);
}

// ---- device error counts

async function devices(slot) {
  try {
    const r = await api.deviceErrors();
    mount(slot, r.devices.length
      ? h('div', { class: 'tablewrap' }, h('table', { class: 'grid' },
        h('thead', {}, h('tr', {}, h('th', {}, 'Device'), h('th', { class: 'num' }, 'Errors'))),
        h('tbody', {}, [...r.devices].sort((a, b) => b.errors - a.errors).map((d) => h('tr', { class: 'bad' },
          h('td', { class: 'mono' }, d.device), h('td', { class: 'mono num' }, String(d.errors)))))))
      : null,
    h('p', { class: r.devices.length ? 'muted small' : 'muted' },
      r.devices.length ? `${plural(r.devices.length, 'device')} with errors, of ${r.scanned}.`
        : `No device errors: ${r.scanned} devices, as SHOW ERROR would say.`));
  } catch (err) {
    mount(slot, refusal(err));
  }
}

// ---- events

function fieldsTable(fields) {
  const rows = [];
  for (const f of fields) {
    if (f.group && rows.length) rows.push(h('tr', { class: 'gap' }, h('td', { colspan: 4 })));
    rows.push(f.text != null
      ? h('tr', {}, h('td', { colspan: 4, class: 'mono pre' }, f.text))
      : h('tr', {},
        h('td', { class: f.indent ? `ind${Math.min(f.indent, 3)}` : null }, f.description),
        h('td', { class: 'mono' }, f.range || ''),
        h('td', { class: 'mono' }, f.value),
        h('td', {}, f.translated || '')));
  }
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid fields' },
    h('thead', {}, h('tr', {}, ['Field', 'Bits', 'Value', 'Meaning'].map((x) => h('th', {}, x)))),
    h('tbody', {}, rows)));
}

async function showEvent(panel, n, me) {
  mount(panel, h('p', { class: 'muted' }, `Translating event ${n}… ELV reads the whole file, a few seconds.`));
  try {
    const r = await api.errorlogEvent(n);
    const e = r.event;
    mount(panel, h('div', { class: 'panel' },
      h('div', { class: 'titlebar' }, h('h3', {}, `Event ${e.number}: ${e.type}`),
        h('button', { type: 'button', onclick: () => mount(panel) }, 'Close')),
      h('p', { class: 'muted small' }, `${when(e.time)} on ${e.node}, ${CLASS_LABEL[e.class] || e.class}.` +
        (e.type === 'Crash Restart' ? ' CLUE\'s summary of the crash is under Crashes, below.' : '')),
      fieldsTable(r.fields)));
  } catch (err) {
    mount(panel, denied(err, me, 'the error log'));
  }
}

function eventsTable(events, cls, panel, me) {
  const shown = (cls ? events.filter((e) => e.class === cls) : events).slice().reverse();   // newest first
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid events' },
    h('thead', {}, h('tr', {}, ['Event', 'When', 'Type', 'Class', 'Node'].map((x) => h('th', {}, x)))),
    h('tbody', {}, shown.length ? shown.map((e) => h('tr', { class: e.class === 'BUGCHECKS' ? 'bad' : null },
      h('td', { class: 'mono num' }, h('button', { type: 'button', class: 'linkish mono', title: 'Translate this event',
        onclick: () => showEvent(panel, e.number, me) }, String(e.number))),
      h('td', { class: 'mono nowrap' }, when(e.time)),
      h('td', {}, e.type),
      h('td', {}, CLASS_LABEL[e.class] || e.class),
      h('td', { class: 'mono' }, e.node)))
      : h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'No event in this range')))));
}

async function events(slot, me, state) {
  mount(slot, h('p', { class: 'muted' }, 'Reading the error log… ELV takes a few seconds.'));
  try {
    const r = await api.errorlog(Number(state.days));
    const counts = {};
    for (const e of r.events) counts[e.class] = (counts[e.class] || 0) + 1;
    const panel = h('div');
    const box = h('div');
    const draw = () => mount(box, eventsTable(r.events, state.cls, panel, me));
    const range = h('select', { 'aria-label': 'Range', onchange: (ev) => { state.days = ev.target.value; events(slot, me, state); } },
      RANGES.map(([k, label]) => h('option', { value: k, selected: k === state.days }, label)));
    const cls = h('select', { 'aria-label': 'Class', onchange: (ev) => { state.cls = ev.target.value; draw(); } },
      h('option', { value: '', selected: !state.cls }, `Every class (${r.events.length})`),
      Object.keys(counts).sort().map((k) => h('option', { value: k, selected: k === state.cls }, `${CLASS_LABEL[k] || k} (${counts[k]})`)));
    draw();
    mount(slot, h('div', { class: 'cmdline' }, range, cls), panel, box,
      r.truncated ? h('p', { class: 'muted small' }, 'Cut short: more events than Steward lists. Choose a shorter range.') : null);
  } catch (err) {
    mount(slot, denied(err, me, 'the error log'));
  }
}

// ---- crashes

async function showCrash(panel, name, me) {
  mount(panel, h('p', { class: 'muted' }, `Reading ${name}…`));
  try {
    const r = await api.crash(name);
    mount(panel, h('div', { class: 'panel' },
      h('div', { class: 'titlebar' }, h('h3', {}, `Crash ${when(r.time)}`),
        h('button', { type: 'button', onclick: () => mount(panel) }, 'Close')),
      h('dl', { class: 'facts' }, r.summary.flatMap((s) => [h('dt', {}, s.key), h('dd', { class: 'mono' }, s.value)])),
      h('details', {}, h('summary', {}, `The whole listing (${name})`), h('pre', { class: 'listing' }, r.text)),
      r.truncated ? h('p', { class: 'muted small' }, 'The listing is cut short.') : null));
  } catch (err) {
    mount(panel, denied(err, me, 'the crash listings'));
  }
}

async function crashes(slot, me) {
  try {
    const r = await api.crashes();
    const list = [...r.crashes].sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0));   // newest first
    const panel = h('div');
    mount(slot, panel, list.length
      ? h('div', { class: 'tablewrap' }, h('table', { class: 'grid crashes' },
        h('thead', {}, h('tr', {}, ['When', 'Bugcheck', 'Process', 'Module', 'Up for'].map((x) => h('th', {}, x)))),
        h('tbody', {}, list.map((c) => h('tr', {},
          h('td', { class: 'mono nowrap' }, h('button', { type: 'button', class: 'linkish mono', title: 'Show the summary and listing',
            onclick: () => showCrash(panel, c.name, me) }, when(c.time))),
          h('td', {}, c.bugcheck),
          h('td', { class: 'mono' }, c.process),
          h('td', { class: 'mono' }, c.module.split(/\s+/)[0]),
          h('td', { class: 'mono nowrap' }, c.uptime))))))
      : h('p', { class: 'muted' }, 'No crash listing: CLUE writes one when the system restarts after a crash.'),
    list.length ? h('p', { class: 'muted small' }, `${plural(list.length, 'listing')} by CLUE in SYS$ERRORLOG.`) : null);
  } catch (err) {
    mount(slot, denied(err, me, 'the crash listings'));
  }
}

// ---- OPCOM's log

function opcomList(messages, filter, limit) {
  const f = filter.trim().toUpperCase();
  const shown = f ? messages.filter((m) => `${m.from || ''} ${m.text}`.toUpperCase().includes(f)) : messages;
  return [
    h('ul', { class: 'opcom' }, shown.slice(0, limit).map((m) => h('li', { class: m.stamp ? 'muted' : null },
      h('div', { class: 'small muted' }, h('span', { class: 'mono' }, when(m.time)), m.from ? ` from ${m.from}${m.node ? ` on ${m.node}` : ''}` : ''),
      h('pre', { class: 'mono' }, m.text)))),
    shown.length ? null : h('p', { class: 'muted' }, f ? 'No message matches' : 'No message'),
    shown.length > limit ? h('p', { class: 'muted small' }, `${limit} of ${shown.length} shown.`) : null,
  ];
}

async function opcom(slot, me, state) {
  mount(slot, h('p', { class: 'muted' }, 'Reading OPERATOR.LOG…'));
  try {
    const r = await api.operatorLog(state.stamps);
    const box = h('div');
    let limit = OPCOM_PAGE;
    const more = h('button', { type: 'button', onclick: () => { limit += OPCOM_PAGE; draw(); } }, 'Show more');
    function draw() {
      mount(box, opcomList(r.messages, state.filter, limit));
      more.hidden = r.messages.length <= limit;
    }
    const input = h('input', { type: 'search', class: 'short', value: state.filter, placeholder: 'Filter', 'aria-label': 'Filter messages',
      spellcheck: 'false', oninput: (ev) => { state.filter = ev.target.value; limit = OPCOM_PAGE; draw(); } });
    const stamps = h('label', {}, h('input', { type: 'checkbox', checked: state.stamps, onchange: (ev) => { state.stamps = ev.target.checked; opcom(slot, me, state); } }),
      ' Hourly time stamps');
    draw();
    mount(slot, h('div', { class: 'cmdline' }, input, stamps), box, more,
      h('p', { class: 'muted small' }, `Newest first, from ${r.file || 'OPERATOR.LOG'}${r.truncated ? `; the newest ${r.messages.length} messages` : ''}.`));
  } catch (err) {
    mount(slot, denied(err, me, 'OPCOM\'s log'));
  }
}

export async function errorlogView(ctx) {
  const me = ctx.me;
  const devSlot = h('div', {}, h('p', { class: 'muted' }, 'Reading…'));
  const evSlot = h('div');
  const crashSlot = h('div', {}, h('p', { class: 'muted' }, 'Reading…'));
  const opSlot = h('div');
  const evState = { days: '30', cls: '' };
  const opState = { stamps: false, filter: '' };

  function loadAll() {
    return Promise.all([devices(devSlot), events(evSlot, me, evState), crashes(crashSlot, me), opcom(opSlot, me, opState)]);
  }
  // A first check that the session is alive, so a lost one goes to sign-in.
  try {
    await api.deviceErrors();
    ctx.touched();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
  }
  loadAll();
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Error log'),
      h('button', { type: 'button', onclick: () => loadAll() }, 'Refresh')),
    h('p', { class: 'muted' }, 'What OpenVMS records about its devices and itself: error counts, the error log (translated by ELV), crashes and OPCOM\'s messages, as OpenVMS lets you read them.'),
    h('h3', {}, 'Device errors'), devSlot,
    h('h3', {}, 'Events'), evSlot,
    h('h3', {}, 'Crashes'), crashSlot,
    h('h3', {}, 'Operator log'), opSlot,
    h('p', { class: 'muted small' }, 'Read-only: start a new error log or operator log at a terminal.'),
  ];
}
