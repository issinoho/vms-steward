// access.js - access history: who reached the system, when, from where and how
// (Phase 6, D13).
//
// One list merged by the server from accounting, the security audit journal,
// OpenSSH's logs, Steward's own log and the live process list, all read as you. A
// source OpenVMS will not let you read is named with its own message, and the rest
// are still shown.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { vmsDate, refusal } from './fmt.js';

const WINDOWS = [
  { label: 'last hour', secs: 3600 },
  { label: 'last 24 hours', secs: 86400 },
  { label: 'last 7 days', secs: 7 * 86400 },
  { label: 'last 30 days', secs: 30 * 86400 },
];
const ROUTES = ['SSH', 'TELNET', 'DECnet', 'LAT', 'local', 'batch', 'network', 'Steward'];
const OUTCOMES = [
  { value: '', label: 'everything' },
  { value: 'connected', label: 'connected now' },
  { value: 'session', label: 'sessions' },
  { value: 'failure', label: 'failures' },
  { value: 'breakin', label: 'break-ins' },
];
const SOURCES = {
  accounting: 'Accounting',
  audit: 'Audit journal',
  ssh: 'SSH logs',
  steward: 'Steward log',
  live: 'Live processes',
};
const KIND = {
  connected: { label: 'Connected', cls: 'tag on' },
  session: { label: 'Session', cls: 'tag' },
  failure: { label: 'Failed', cls: 'tag warn' },
  breakin: { label: 'Break-in', cls: 'tag warn solid' },
};

const state = { window: 86400, user: '', route: '', outcome: '' };   // kept for the way back


function duration(e) {
  if (e.kind === 'connected') return `${span(Math.floor(Date.now() / 1000) - e.start)} so far`;
  if (e.end === null || e.end === undefined) return e.kind === 'session' ? 'not recorded' : '';
  return span(e.end - e.start);
}

function span(s) {
  s = Math.max(0, s);
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, '0')}s`;
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), mm = Math.floor((s % 3600) / 60);
  return d ? `${d}d ${hh}h` : `${hh}h ${String(mm).padStart(2, '0')}m`;
}

function select(options, value, label) {
  return h('select', { 'aria-label': label },
    options.map((o) => h('option', { value: o.value, selected: o.value === value }, o.label)));
}

// The filter, as a DCL command line would put it.
function filterForm(onSubmit) {
  const win = select(WINDOWS.map((w) => ({ value: String(w.secs), label: w.label })), String(state.window), 'Since');
  const user = h('input', { type: 'search', class: 'short', value: state.user, maxlength: 31, spellcheck: 'false',
    autocapitalize: 'characters', 'aria-label': 'User', placeholder: '*' });
  const route = select([{ value: '', label: 'any route' }, ...ROUTES.map((r) => ({ value: r, label: r }))], state.route, 'Route');
  const outcome = select(OUTCOMES, state.outcome, 'Outcome');
  return h('form', { class: 'cmdline', role: 'search',
    onsubmit: (ev) => {
      ev.preventDefault();
      Object.assign(state, { window: Number(win.value), user: user.value.trim(), route: route.value, outcome: outcome.value });
      onSubmit();
    } },
    h('span', { class: 'cmd' }, '$ show access /since='), win,
    h('span', { class: 'cmd' }, '/user='), user,
    h('span', { class: 'cmd' }, '/route='), route,
    h('span', { class: 'cmd' }, '/outcome='), outcome,
    h('button', { type: 'submit' }, 'Show'));
}

function summary(events) {
  const count = (k) => events.filter((e) => e.kind === k).length;
  const failFrom = new Set(events.filter((e) => e.kind !== 'session' && e.kind !== 'connected' && e.from).map((e) => e.from));
  const users = new Set(events.filter((e) => e.kind === 'session' || e.kind === 'connected').map((e) => e.user).filter(Boolean));
  const fig = (n, label, warn) => h('div', { class: warn && n ? 'figure warn' : 'figure' },
    h('span', { class: 'n' }, String(n)), h('span', { class: 'l' }, label));
  return h('div', { class: 'figures' },
    fig(count('connected'), 'connected now'),
    fig(count('session'), 'sessions'),
    fig(users.size, users.size === 1 ? 'user' : 'users'),
    fig(count('failure'), 'failed sign-ins', true),
    fig(count('breakin'), 'break-ins', true),
    fig(failFrom.size, failFrom.size === 1 ? 'address failing' : 'addresses failing', true));
}

// Which sources were read; a refused one with OpenVMS's message.
function sources(src, me) {
  const refused = Object.entries(src).filter(([, s]) => !s.read);
  const chips = h('ul', { class: 'sources' }, Object.entries(SOURCES).map(([k, label]) => {
    const s = src[k] || { read: false };
    return h('li', { class: s.read ? 'ok' : 'no', title: s.read ? 'Read' : (s.vms_message || 'Not read') },
      h('span', { class: 'led', 'aria-hidden': 'true' }), label, s.read ? null : h('span', { class: 'sr' }, ' (not read)'));
  }));
  if (!refused.length) return chips;
  const can = me.authorized_privileges.some((p) => p === 'SYSPRV' || p === 'READALL');
  const on = me.current_privileges.some((p) => p === 'SYSPRV' || p === 'READALL');
  return h('div', {}, chips,
    h('div', { class: 'refusal' },
      h('pre', { class: 'vmsmsg' }, refused.map(([k, s]) => `${SOURCES[k] || k}: ${s.vms_message || s.vms_status}`).join('\n')),
      h('p', { class: 'muted' }, on
        ? 'OpenVMS refused these files even with your privileges switched on: their protection or the directories\' does not let you read them.'
        : can
          ? h('span', {}, 'These files need SYSPRV or READALL. You hold one: switch it on under ', h('a', { href: '#/account' }, 'My account'), ' to read them.')
          : 'These files need SYSPRV or READALL, which your account does not hold. What is shown comes from the sources you may read.')));
}

function row(e) {
  const k = KIND[e.kind] || KIND.session;
  return h('tr', { class: e.kind === 'failure' || e.kind === 'breakin' ? 'bad' : '' },
    h('td', { class: 'nowrap mono' }, vmsDate(e.start)),
    h('td', {}, h('span', { class: k.cls }, k.label)),
    h('td', { class: 'mono' }, e.user ? h('a', { href: `#/users/${encodeURIComponent(e.user)}` }, e.user) : h('span', { class: 'muted' }, '—')),
    h('td', {}, e.route),
    h('td', { class: 'mono' }, e.from || h('span', { class: 'muted' }, '—'), e.terminal ? h('span', { class: 'muted small' }, ` ${e.terminal}`) : null),
    h('td', { class: 'nowrap' }, duration(e)),
    h('td', { class: 'small' }, e.detail || ''));
}

export async function accessView(ctx) {
  const slot = h('div');
  const stamp = h('span', { class: 'muted small' });

  let first = true;
  async function load() {
    const until = Math.floor(Date.now() / 1000);
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.access({ since: until - state.window, until, user: state.user, route: state.route,
        outcome: state.outcome, limit: 2000 });
      ctx.touched();
      stamp.textContent = `as of ${vmsDate(until)}`;
      const table = h('div', { class: 'tablewrap' },
        h('table', { class: 'grid access' },
          h('thead', {}, h('tr', {}, ['When', '', 'User', 'Route', 'From', 'Duration', 'Detail'].map((x) => h('th', {}, x)))),
          h('tbody', {}, r.events.length ? r.events.map(row)
            : h('tr', {}, h('td', { colspan: 7, class: 'muted' }, 'Nothing in this window')))));
      mount(slot, sources(r.sources, ctx.me), summary(r.events), table,
        r.truncated ? h('p', { class: 'muted small' }, `Showing the newest ${r.events.length}. Narrow the window or filter to see the rest.`) : null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        if (first) throw err;   // to the shell, which returns to sign-in
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
    h('div', { class: 'titlebar' }, h('h2', {}, 'Access history'), stamp),
    h('p', { class: 'muted' },
      'Who reached the system, when, from where and how: sessions from accounting and the live process list, SSH sign-in methods from OpenSSH\'s logs, failures and break-ins from the security audit journal, and sign-ins to Steward itself. All read as you.'),
    filterForm(() => load().catch(() => {})),
    slot,
  ];
}
