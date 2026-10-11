// logicals.js - logical names, read-only (Phase 7, D14).
//
// The shareable tables, the names in one, and what a name translates to. Listing a
// table runs SHOW LOGICAL as you (a short-lived process that is you), so you see
// what you would see at a terminal: a table you may not read is answered as one that
// does not exist, as SHOW LOGICAL answers. Process and job tables of this service are
// never shown: they would be the service's own, not yours.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';

const remembered = { table: 'LNM$SYSTEM_TABLE', filter: '' };   // for the way back

const KINDS = [
  ['system', 'System'], ['cluster', 'Cluster'], ['yours', 'Your group'], ['group', 'Other groups'],
  ['job', 'Jobs'], ['other', 'Other'],
];

function tags(list, warn) {
  if (!list || !list.length) return null;
  return h('span', { class: 'tags' }, list.map((a) => h('span', { class: warn && warn.has(a) ? 'tag on' : 'tag' }, a)));
}

const NAME_FLAGS = new Set(['no_alias', 'confine', 'table', 'clusterwide']);

// The tables, grouped, as links; the current one marked.
function tablesPanel(r, current, onPick) {
  const groups = new Map(KINDS.map(([k]) => [k, []]));
  for (const t of r.tables) {
    const kind = t.name === r.your_group_table ? 'yours' : t.kind;
    (groups.get(kind) || groups.get('other')).push(t);
  }
  return h('nav', { class: 'panel tables', 'aria-label': 'Logical name tables' },
    KINDS.filter(([k]) => groups.get(k).length).map(([k, label]) => [
      h('h4', {}, label),
      h('ul', {}, groups.get(k).map((t) => h('li', {},
        t.listable
          ? h('a', { href: '#/logicals', class: t.name === current ? 'current mono' : 'mono',
              'aria-current': t.name === current ? 'true' : false,
              onclick: (ev) => { ev.preventDefault(); onPick(t.name); } }, t.name)
          : h('span', { class: 'mono muted', title: 'Not listed here' }, t.name)))),
    ]));
}

// What one name leads to: each equivalence, then each name it translates to in turn.
function chain(detail) {
  const n = detail.logical;
  return h('div', { class: 'chain' },
    n.equivalences.map((e, i) => h('div', { class: 'chainrow' },
      h('span', { class: 'mono' }, e.value === '' ? '""' : e.value),
      tags(e.attributes),
      (detail.translations[i] || []).map((s) => [
        h('span', { class: 'arrow', 'aria-hidden': 'true' }, '→'),
        h('span', { class: 'mono' }, s.name, ' = ', s.value),
        h('span', { class: 'muted small' }, ` (${s.table})`),
        tags(s.attributes),
      ]),
      !(detail.translations[i] || []).length && !e.attributes.includes('terminal')
        ? h('span', { class: 'muted small' }, ' (no further translation)') : null)),
    n.more_equivalences ? h('p', { class: 'muted small' }, `and ${n.more_equivalences} more`) : null);
}

function namesTable(ctx, t) {
  const rows = [];
  for (const n of t.names) {
    const slot = h('td', { colspan: 4 });
    const more = h('tr', { class: 'detail', hidden: true }, slot);
    const open = async () => {
      if (!more.hidden) { more.hidden = true; return; }
      more.hidden = false;
      mount(slot, h('span', { class: 'muted' }, 'Translating…'));
      try {
        const d = await api.logical(t.name, n.name);
        ctx.touched();
        mount(slot, chain(d));
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) { ctx.authLost(); return; }
        mount(slot, refusal(err));
      }
    };
    rows.push(h('tr', {},
      h('td', {}, h('button', { type: 'button', class: 'linkish mono', onclick: open, title: 'What it translates to' }, n.name)),
      h('td', {}, h('span', { class: 'tag' }, n.mode)),
      h('td', { class: 'mono eqs' }, n.equivalences.map((e) => h('div', {},
        e.value === '' ? h('span', { class: 'muted' }, '""') : e.value, ' ', tags(e.attributes)))),
      h('td', {}, tags(n.attributes, NAME_FLAGS))), more);
  }
  return h('div', { class: 'tablewrap' },
    h('table', { class: 'grid logicals' },
      h('thead', {}, h('tr', {}, ['Name', 'Mode', 'Equivalence', 'Attributes'].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 4, class: 'muted' }, 'No match')))));
}

export async function logicalsView(ctx) {
  const side = h('div');
  const slot = h('div');
  const input = h('input', { type: 'search', class: 'short', value: remembered.filter, maxlength: 61,
    spellcheck: 'false', autocapitalize: 'characters', 'aria-label': 'Filter', placeholder: '*' });
  const tableName = h('b', {}, remembered.table);
  let tables = null;
  let first = true;

  async function load() {
    tableName.textContent = remembered.table;
    if (tables) mount(side, tablesPanel(tables, remembered.table, pick));
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.logicals({ table: remembered.table, filter: remembered.filter });
      ctx.touched();
      if (!r.tables.length) {
        mount(slot, h('p', { class: 'muted' }, `No names in ${r.table} match ${r.filter}.`));
        return;
      }
      mount(slot, r.tables.map((t) => [
        h('div', { class: 'tablehead' },
          h('h3', { class: 'mono' }, t.name),
          h('dl', { class: 'facts small-facts' },
            h('dt', {}, 'Protection'), h('dd', { class: 'mono' }, t.protection || '—'),
            h('dt', {}, 'Owner'), h('dd', { class: 'mono' }, t.owner || '—'),
            h('dt', {}, 'Mode'), h('dd', {}, t.mode || '—'),
            h('dt', {}, 'Attributes'), h('dd', {}, tags(t.attributes) || '—'))),
        namesTable(ctx, t),
        h('p', { class: 'muted small' }, `${t.names.length} ${t.names.length === 1 ? 'name' : 'names'}`),
      ]), r.truncated ? h('p', { class: 'muted small' }, 'Only the first 2000 are shown: narrow the filter.') : null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        if (first) throw err;
        ctx.authLost();
        return;
      }
      mount(slot, refusal(err, err instanceof ApiError && err.status === 404
        ? 'OpenVMS answers the same for a table that does not exist and one you may not read. With SYSPRV or GRPPRV switched on (My account), other groups\' tables can be read.'
        : null));
    } finally {
      first = false;
    }
  }
  function pick(name) {
    remembered.table = name;
    load().catch(() => {});
  }

  try {
    tables = await api.logicalTables();
    ctx.touched();
    mount(side, tablesPanel(tables, remembered.table, pick));
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    mount(side, refusal(err));
  }
  await load();
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Logical names')),
    h('p', { class: 'muted' },
      'The shareable logical name tables and their names, read as you: SHOW LOGICAL runs as you, so you see what you would at a terminal. Click a name to see what it translates to.'),
    h('div', { class: 'lnm' }, side, h('div', { class: 'lnm-main' },
      h('form', { class: 'cmdline', role: 'search',
        onsubmit: (ev) => { ev.preventDefault(); remembered.filter = input.value.trim(); load().catch(() => {}); } },
        h('span', { class: 'cmd' }, '$ show logical /table=', tableName, ' '), input,
        h('button', { type: 'submit' }, 'Show')),
      slot)),
  ];
}
