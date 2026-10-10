// rights.js - users and rights identifiers, read-only (Phase 2).
//
// Every request runs as the signed-in user, so what OpenVMS refuses is refused here
// too, with its own message. These views never guess at permissions: they ask, and
// show the answer. A 401 is thrown to the shell, which returns to sign-in.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { vmsDate, keycaps, refusal } from './fmt.js';

const PAGE = 50;
const remembered = { users: '', identifiers: '', type: 'general' };   // for the way back

const userHref = (name) => `#/users/${encodeURIComponent(name)}`;
const identHref = (name) => `#/identifiers/${encodeURIComponent(name)}`;

function rethrowAuth(err) {
  if (err instanceof ApiError && err.status === 401) throw err;
}

// Flags that matter at a glance get a colour; the rest are plain tags.
const WARN_FLAGS = new Set(['DISUSER', 'PWD_EXPIRED', 'PWD2_EXPIRED', 'CAPTIVE', 'RESTRICTED']);
function tags(list, warn = WARN_FLAGS) {
  return h('span', { class: 'tags' }, list.map((f) => h('span', { class: warn.has(f) ? 'tag warn' : 'tag' }, f)));
}

// A filter box in the style of a DCL command line. Wildcards * and % as in DCL; plain
// text matches anywhere in the name (and, for users, the owner).
function filterForm(prompt, value, onSubmit, extra) {
  const input = h('input', { type: 'search', value, maxlength: 31, spellcheck: 'false',
    autocapitalize: 'characters', 'aria-label': 'Filter', placeholder: '*' });
  return h('form', { class: 'cmdline', role: 'search',
    onsubmit: (ev) => { ev.preventDefault(); onSubmit(input.value.trim()); } },
    h('span', { class: 'cmd' }, prompt), input, extra || null,
    h('button', { type: 'submit' }, 'Show'));
}

// A paged table: fetch(after) returns { rows, next }; rows are <tr> elements.
function pagedTable(head, fetchPage, onError) {
  const tbody = h('tbody');
  const more = h('button', { type: 'button', class: 'ghost more', hidden: true }, 'More');
  const count = h('span', { class: 'muted small' });
  let next = null;
  let shown = 0;
  async function load(reset) {
    more.disabled = true;
    try {
      const page = await fetchPage(reset ? null : next);
      if (reset) { tbody.replaceChildren(); shown = 0; }
      tbody.append(...page.rows);
      shown += page.rows.length;
      next = page.next;
      more.hidden = !next;
      count.textContent = shown ? `${shown}${next ? '+' : ''} shown` : '';
      if (!shown) tbody.append(h('tr', {}, h('td', { colspan: head.length, class: 'muted' }, 'No match')));
      el.hidden = false;
    } catch (err) {
      rethrowAuth(err);
      if (reset) el.hidden = true;   // nothing to show under the refusal
      onError(err);
    } finally {
      more.disabled = false;
    }
  }
  more.addEventListener('click', () => load(false).catch(() => {}));
  const el = h('div', { class: 'tablewrap' },
    h('table', { class: 'grid' }, h('thead', {}, h('tr', {}, head.map((x) => h('th', {}, x)))), tbody),
    h('div', { class: 'tablefoot' }, count, more));
  return { el, load };
}

// ---------------------------------------------------------------- users

export async function usersView(ctx) {
  const slot = h('div');
  const table = pagedTable(['Username', 'Owner', 'UIC', 'Account', 'Flags', 'Last login'],
    async (after) => {
      const r = await api.users({ filter: remembered.users, after, limit: PAGE });
      ctx.touched();
      return {
        next: r.next,
        rows: r.users.map((u) => u.restricted
          ? h('tr', {}, h('td', {}, h('a', { href: userHref(u.username) }, u.username)),
              h('td', { colspan: 5, class: 'muted' }, 'record not readable as you'))
          : h('tr', {},
              h('td', {}, h('a', { href: userHref(u.username), class: 'mono' }, u.username)),
              h('td', {}, u.owner),
              h('td', { class: 'mono' }, u.uic),
              h('td', { class: 'mono' }, u.account),
              h('td', {}, tags(u.flags)),
              h('td', { class: 'mono nowrap' }, u.last_login_interactive ? vmsDate(u.last_login_interactive, false) : '(none)'))),
      };
    },
    (err) => mount(slot, refusal(err, usersHint(ctx.me))));

  await table.load(true);
  return [
    h('h2', {}, 'Users'),
    h('p', { class: 'muted' }, 'The accounts in SYSUAF, read as you. Wildcards * and % work as in DCL; plain text also matches the owner.'),
    filterForm('$ authorize show', remembered.users, (f) => { remembered.users = f; mount(slot); table.load(true); }),
    slot,
    table.el,
  ];
}

function usersHint(me) {
  const sysprv = me.authorized_privileges.includes('SYSPRV');
  const on = me.current_privileges.includes('SYSPRV') || me.current_privileges.includes('READALL');
  return h('span', {},
    'Listing users reads SYSUAF, which OpenVMS opens only with SYSPRV or READALL. ',
    sysprv && !on ? [h('a', { href: '#/account' }, 'Switch SYSPRV on'), ' for this session, or read '] : 'You can still read ',
    h('a', { href: userHref(me.username) }, 'your own record'), '.');
}

// ---------------------------------------------------------------- one user

// Quotas in AUTHORIZE's three columns, row by row.
const QUOTA_LAYOUT = [
  ['Maxjobs', 'maxjobs'], ['Fillm', 'fillm'], ['Bytlm', 'bytlm'],
  ['Maxacctjobs', 'maxacctjobs'], ['Shrfillm', 'shrfillm'], ['Pbytlm', 'pbytlm'],
  ['Maxdetach', 'maxdetach'], ['BIOlm', 'biolm'], ['JTquota', 'jtquota'],
  ['Prclm', 'prclm'], ['DIOlm', 'diolm'], ['WSdef', 'wsdef'],
  ['Prio', 'prio'], ['ASTlm', 'astlm'], ['WSquo', 'wsquo'],
  ['Queprio', 'queprio'], ['TQElm', 'tqelm'], ['WSextent', 'wsextent'],
  ['CPU', 'cpu'], ['Enqlm', 'enqlm'], ['Pgflquo', 'pgflquo'],
];

// CPU time in 10 ms ticks, as AUTHORIZE writes it: d hh:mm:ss.cc, or (none).
function cpuTime(ticks) {
  if (!ticks) return '(none)';
  const cs = ticks % 100, s = Math.floor(ticks / 100);
  const p = (n) => String(n).padStart(2, '0');
  return `${Math.floor(s / 86400)} ${p(Math.floor(s / 3600) % 24)}:${p(Math.floor(s / 60) % 60)}:${p(s % 60)}.${p(cs)}`;
}

const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
const KINDS = [['Network', 'network'], ['Batch', 'batch'], ['Local', 'local'], ['Dialup', 'dialup'], ['Remote', 'remote']];

// Access hours as AUTHORIZE draws them: a cell per hour, lit where access is allowed.
function hoursGrid(r) {
  const header = (digit) => h('span', { class: 'hrs head' },
    Array.from({ length: 24 }, (_, i) => h('span', {}, digit(i))));
  const row = (blocked) => {
    const set = new Set(blocked);
    return h('span', { class: 'hrs', title: set.size === 24 ? 'No access' : set.size ? `No access in ${set.size} hours` : 'Full access' },
      Array.from({ length: 24 }, (_, i) => h('span', { class: set.has(i) ? 'off' : 'on' })));
  };
  return h('div', { class: 'hourgrid', role: 'table', 'aria-label': 'Access hours' },
    h('span', {}), h('span', { class: 'cap' }, 'Primary'), h('span', { class: 'cap' }, 'Secondary'),
    h('span', {}), header((i) => Math.floor(i / 10)), header((i) => Math.floor(i / 10)),
    h('span', {}), header((i) => i % 10), header((i) => i % 10),
    KINDS.map(([label, k]) => [h('span', { class: 'kind' }, label), row(r[k].primary), row(r[k].secondary)]));
}

export async function userView(ctx, name) {
  let u;
  try {
    u = await api.user(name);
    ctx.touched();
  } catch (err) {
    rethrowAuth(err);
    return [h('p', {}, h('a', { href: '#/users' }, '← Users')), h('h2', { class: 'mono' }, name),
      refusal(err, err.status === 403
        ? 'OpenVMS lets you read your own record, your UIC group\'s with GRPPRV, and anyone\'s with SYSPRV.'
        : null)];
  }
  const held = h('div', {}, h('span', { class: 'muted' }, 'Reading…'));
  api.userIdentifiers(name).then((r) => {
    ctx.touched();
    mount(held, r.identifiers.length
      ? h('table', { class: 'grid' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Identifier'), h('th', {}, 'Value'), h('th', {}, 'Attributes'))),
          h('tbody', {}, r.identifiers.map((i) => h('tr', {},
            h('td', {}, h('a', { href: identHref(i.name), class: 'mono' }, i.name)),
            h('td', { class: 'mono' }, i.value), h('td', {}, tags(i.attributes, new Set()))))))
      : h('span', { class: 'muted' }, 'None'));
  }).catch((err) => {
    if (err instanceof ApiError && err.status === 401) { ctx.authLost(); return; }
    mount(held, refusal(err));
  });

  const pw = u.password;
  const defaults = new Set(u.default_privileges);
  return [
    h('p', {}, h('a', { href: '#/users' }, '← Users')),
    h('h2', { class: 'mono' }, u.username),
    u.owner ? h('p', { class: 'muted' }, u.owner) : null,
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'UIC'), h('dd', { class: 'mono' }, u.uic),
      h('dt', {}, 'Account'), h('dd', { class: 'mono' }, u.account || '—'),
      h('dt', {}, 'CLI'), h('dd', { class: 'mono' }, `${u.cli}  (tables ${u.clitables})`),
      h('dt', {}, 'Default'), h('dd', { class: 'mono' }, `${u.default_device}${u.default_directory}`),
      h('dt', {}, 'LGICMD'), h('dd', { class: 'mono' }, u.lgicmd || '—'),
      h('dt', {}, 'Expiration'), h('dd', { class: 'mono' }, vmsDate(u.expiration, false)),
      h('dt', {}, 'Last login'), h('dd', { class: 'mono' },
        `${vmsDate(u.last_login_interactive, false)} (interactive), ${vmsDate(u.last_login_noninteractive, false)} (non-interactive)`),
      h('dt', {}, 'Password'), h('dd', { class: 'mono' },
        pw.pre_expired ? '(pre-expired)' : `changed ${vmsDate(pw.changed, false)}`,
        `, lifetime ${pw.lifetime_days === null ? '(none)' : `${pw.lifetime_days} days`}, minimum ${pw.minimum_length}`),
      h('dt', {}, 'Login fails'), h('dd', { class: pw.login_failures ? 'mono warn-text' : 'mono' }, String(pw.login_failures)))),
    h('h3', {}, 'Flags'),
    u.flags.length ? tags(u.flags) : h('span', { class: 'muted' }, 'None'),
    h('h3', {}, 'Days'),
    h('ul', { class: 'days' }, DAYS.map((d) => h('li', { class: u.secondary_days.includes(d) ? 'secondary' : 'primary', title: u.secondary_days.includes(d) ? 'Secondary day' : 'Primary day' }, d))),
    h('h3', {}, 'Access hours'),
    hoursGrid(u.restricted_hours),
    h('h3', {}, 'Authorized privileges — lit: on by default'),
    keycaps(u.authorized_privileges, 'None', defaults),
    h('h3', {}, 'Quotas and limits'),
    h('dl', { class: 'quotas' }, QUOTA_LAYOUT.map(([label, k]) => [
      h('dt', {}, label), h('dd', { class: 'mono' }, k === 'cpu' ? cpuTime(u.quotas.cpu) : String(u.quotas[k]))])),
    h('h3', {}, 'Identifiers held'),
    held,
  ];
}

// ---------------------------------------------------------------- identifiers

export async function identifiersView(ctx) {
  const slot = h('div');
  const type = h('select', { 'aria-label': 'Kind of identifier' },
    [['general', 'General'], ['uic', 'UIC'], ['all', 'All']].map(([v, l]) =>
      h('option', { value: v, selected: remembered.type === v }, l)));
  const table = pagedTable(['Identifier', 'Value', 'Attributes'],
    async (after) => {
      const r = await api.identifiers({ type: remembered.type, filter: remembered.identifiers, after, limit: PAGE });
      ctx.touched();
      return {
        next: r.next,
        rows: r.identifiers.map((i) => h('tr', {},
          h('td', {}, h('a', { href: identHref(i.name), class: 'mono' }, i.name)),
          h('td', { class: 'mono' }, i.value),
          h('td', {}, tags(i.attributes, new Set())))),
      };
    },
    (err) => mount(slot, refusal(err)));
  type.addEventListener('change', () => { remembered.type = type.value; mount(slot); table.load(true); });

  await table.load(true);
  return [
    h('h2', {}, 'Rights identifiers'),
    h('p', { class: 'muted' }, 'The rights database, sorted by name as AUTHORIZE lists it. General identifiers by default; UIC identifiers are the users and groups.'),
    filterForm('$ authorize show/identifier', remembered.identifiers,
      (f) => { remembered.identifiers = f; mount(slot); table.load(true); }, type),
    slot,
    table.el,
  ];
}

export async function identifierView(ctx, name) {
  let id, holders;
  const back = h('p', {}, h('a', { href: '#/identifiers' }, '← Rights identifiers'));
  try {
    [id, holders] = await Promise.all([api.identifier(name), api.holders(name)]);
    ctx.touched();
  } catch (err) {
    rethrowAuth(err);
    return [back, h('h2', { class: 'mono' }, name), refusal(err)];
  }
  return [
    back,
    h('h2', { class: 'mono' }, id.name),
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'Value'), h('dd', { class: 'mono' }, id.value),
      h('dt', {}, 'Kind'), h('dd', {}, id.type === 'uic' ? 'UIC identifier' : 'General identifier'),
      h('dt', {}, 'Attributes'), h('dd', {}, id.attributes.length ? tags(id.attributes, new Set()) : h('span', { class: 'muted' }, 'None')))),
    id.type === 'uic' ? h('p', {}, 'The account: ', h('a', { href: userHref(id.name), class: 'mono' }, id.name)) : null,
    h('h3', {}, `Holders (${holders.holders.length})`),
    holders.holders.length
      ? h('table', { class: 'grid' },
          h('thead', {}, h('tr', {}, h('th', {}, 'Holder'), h('th', {}, 'UIC'), h('th', {}, 'Attributes'))),
          h('tbody', {}, holders.holders.map((x) => h('tr', {},
            h('td', {}, x.username ? h('a', { href: userHref(x.username), class: 'mono' }, x.username) : h('span', { class: 'muted' }, '(no name)')),
            h('td', { class: 'mono' }, x.uic),
            h('td', {}, tags(x.attributes, new Set()))))))
      : h('span', { class: 'muted' }, 'None'),
  ];
}

