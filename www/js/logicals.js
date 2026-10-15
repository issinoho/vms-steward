// logicals.js - logical names (Phase 7, D14 and D15).
//
// The shareable tables, the names in one, and what a name translates to. Listing a
// table runs SHOW LOGICAL as you (a short-lived process that is you), so you see
// what you would see at a terminal: a table you may not read is answered as one that
// does not exist, as SHOW LOGICAL answers. Process and job tables of this service are
// never shown: they would be the service's own, not yours.
//
// Defining and deassigning (7b) run as you too, and OpenVMS decides. Two things it
// does quietly are named before you confirm: no_alias removes the name at every
// outer mode, and a deassign takes the outer modes with it.

import { api, ApiError } from './api.js';
import { h, mount, toast } from './dom.js';
import { refusal, vmsMessage } from './fmt.js';
import { dialog, field, toggles } from './edit.js';

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

const MODES = [['user', 'User'], ['super', 'Supervisor'], ['exec', 'Executive']];
const OUTER = { exec: ['super', 'user'], super: ['user'], user: [] };   // less privileged
const MODE_LABEL = Object.fromEntries(MODES);
const hasSysnam = (ctx) => (ctx.me.current_privileges || []).includes('SYSNAM');
const list = (xs) => (xs.length > 1 ? `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}` : xs[0]);

// The modes of name in table that defining it no_alias at mode would remove.
async function outerModes(table, name, mode) {
  try {
    const d = await api.logical(table, name);
    return d.modes.filter((m) => OUTER[mode].includes(m));
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return [];
    throw err;
  }
}

// Define a name in table, or (existing: a GET logical answer) change that one. done()
// redraws. A name already at that mode, or outer modes no_alias would remove, are
// named in the dialog first, and the button pressed again goes ahead.
function defineDialog(ctx, table, existing, done) {
  const n = existing ? existing.logical : null;
  if (n && n.more_equivalences) {   // saving would drop the ones not shown
    toast(`${n.name} has more than 16 equivalences: change it with DEFINE at a terminal.`, 'error');
    return;
  }
  const tableIn = h('input', { value: existing ? existing.table : table, required: true, maxlength: 31,
    spellcheck: 'false', autocapitalize: 'characters', class: 'mono', disabled: !!n });
  const nameIn = h('input', { value: n ? n.name : '', required: true, maxlength: 255, spellcheck: 'false',
    autocapitalize: 'characters', class: 'mono', disabled: !!n });
  const sysnam = hasSysnam(ctx);
  const initial = n ? n.mode : (sysnam ? 'super' : 'user');
  const modeSel = h('select', { disabled: !!n },
    MODES.map(([v, l]) => h('option', { value: v, selected: v === initial }, l)));
  const attrs = toggles(['no_alias', 'confine'], n ? n.attributes.filter((a) => a === 'no_alias' || a === 'confine') : [],
    'Name attributes');
  const rows = h('div', { class: 'eqrows' });
  const eqs = [];
  function addEq(value, on) {
    if (eqs.length >= 16) return;
    const input = h('input', { value: value || '', required: true, maxlength: 255, spellcheck: 'false', class: 'mono',
      'aria-label': `Equivalence ${eqs.length + 1}` });
    const t = toggles(['concealed', 'terminal'], on || [], 'Equivalence attributes');
    const entry = { input, t };
    entry.row = h('div', { class: 'eqrow' }, input, t.el,
      h('button', { type: 'button', class: 'linkish', onclick: () => {
        if (eqs.length < 2) return;
        eqs.splice(eqs.indexOf(entry), 1);
        entry.row.remove();
      } }, 'Remove'));
    eqs.push(entry);
    rows.append(entry.row);
  }
  (n ? n.equivalences : [{ value: '', attributes: [] }]).forEach((e) => addEq(e.value, e.attributes));
  const note = h('p', { class: 'warn-text', hidden: true });
  let sureAlias = false;
  let sureReplace = !!n;
  const reset = () => { note.hidden = true; sureAlias = false; sureReplace = !!n; };
  dialog(n ? `Modify ${n.name} (${MODE_LABEL[n.mode].toLowerCase()} mode)` : 'Define a logical name', h('div', { class: 'editor', oninput: reset, onclick: (ev) => {
    if (ev.target.closest('.keys')) reset();
  } },
    h('div', { class: 'fields' },
      field('Table', tableIn, 'LNM$GROUP is your group table'),
      field('Mode', modeSel, sysnam ? null : 'Supervisor and executive need SYSNAM switched on (My account)')),
    field('Name', nameIn, 'Kept as typed: logical names are case-sensitive'),
    h('h3', {}, 'Equivalences'), rows,
    h('button', { type: 'button', onclick: () => addEq() }, 'Add an equivalence'),
    h('h3', {}, 'Attributes'), attrs.el,
    h('p', { class: 'muted small' }, 'no_alias also removes the name at every outer mode, as OpenVMS does.'),
    note),
  [{ label: n ? 'Save' : 'Define', primary: true, run: async () => {
    const body = { table: tableIn.value.trim().toUpperCase(), name: nameIn.value, mode: modeSel.value,
      attributes: attrs.value(), equivalences: eqs.map((e) => ({ value: e.input.value, attributes: e.t.value() })) };
    if (body.attributes.includes('no_alias') && !sureAlias) {
      const going = await outerModes(body.table, body.name, body.mode);
      sureAlias = true;
      if (going.length) {
        note.textContent = `no_alias also removes ${body.name} at ${list(going.map((m) => MODE_LABEL[m].toLowerCase()))} mode. Press ${n ? 'Save' : 'Define'} again to go ahead.`;
        note.hidden = false;
        return false;
      }
    }
    body.replace = sureReplace;
    let r;
    try {
      r = await api.defineLogical(body);
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 409)) throw err;
      let now = '';
      try {
        const d = await api.logical(body.table, body.name);
        if (d.logical.mode === body.mode) now = ` = ${d.logical.equivalences.map((e) => `"${e.value}"`).join(', ')}`;
      } catch { /* shown without its value */ }
      note.textContent = `${body.name}${now} already exists at ${MODE_LABEL[body.mode].toLowerCase()} mode in ${body.table}. Press ${n ? 'Save' : 'Define'} again to replace it.`;
      note.hidden = false;
      sureReplace = true;
      return false;
    }
    toast(body.replace
      ? vmsMessage('I', 'SUPERSEDE', `previous value of ${r.logical.name} has been superseded`)
      : `${r.logical.name} defined in ${r.table}`);
    done();
    return true;
  } }]);
}

// Deassign the name shown in detail (a GET logical answer): at the chosen mode and
// every outer one, as DEASSIGN does; the dialog names each mode that goes.
function deassignDialog(detail, done) {
  const n = detail.logical;
  const modes = (detail.modes || [n.mode]).filter((m) => m in OUTER);
  const sel = h('select', {}, modes.map((m) => h('option', { value: m }, MODE_LABEL[m])));
  const what = h('p', {});
  const explain = () => {
    const going = modes.filter((x) => x === sel.value || OUTER[sel.value].includes(x));
    what.textContent = `${n.name} will be removed from ${detail.table} at ${list(going.map((m) => MODE_LABEL[m].toLowerCase()))} mode.`;
  };
  sel.addEventListener('change', explain);
  explain();
  dialog(`Deassign ${n.name}`, h('div', {},
    modes.length > 1 ? field('Mode', sel, 'and every outer mode, as DEASSIGN does') : null, what),
  [{ label: 'Deassign', primary: true, danger: true, run: async () => {
    const r = await api.deassignLogical(detail.table, n.name, sel.value);
    toast(`${n.name} deassigned from ${r.table} (${r.removed.join(', ')})`);
    done();
    return true;
  } }]);
}

// The changes offered for one name, under its translation. A name at several modes
// gets a Modify button per mode: the translation shows only the outermost, and
// each button opens the definition at its own mode.
function nameActions(ctx, d, reload) {
  const n = d.logical;
  const modes = (d.modes && d.modes.length ? d.modes : [n.mode]).filter((m) => m in OUTER);
  const edit = async (m, b) => {
    if (m === n.mode) { defineDialog(ctx, d.table, d, reload); return; }
    b.disabled = true;
    try {
      defineDialog(ctx, d.table, await api.logical(d.table, n.name, m), reload);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) { ctx.authLost(); return; }
      toast(err.message, 'error');
    } finally {
      b.disabled = false;
    }
  };
  return h('div', { class: 'actions lnm-actions' },
    modes.length > 1 ? h('span', { class: 'muted small' },
      `At ${list(modes.map((m) => MODE_LABEL[m].toLowerCase()))} mode. Shown above: ${MODE_LABEL[n.mode].toLowerCase()}, the outermost, as SHOW LOGICAL shows it.`) : null,
    modes.map((m) => {
      const b = h('button', { type: 'button' }, modes.length > 1 ? `Modify ${MODE_LABEL[m].toLowerCase()}…` : 'Modify…');
      b.addEventListener('click', () => edit(m, b));
      return b;
    }),
    modes.length ? h('button', { type: 'button', class: 'danger', onclick: () => deassignDialog(d, reload) }, 'Deassign…') : null);
}

function namesTable(ctx, t, reload) {
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
        mount(slot, chain(d), nameActions(ctx, d, reload));
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
        namesTable(ctx, t, () => load().catch(() => {})),
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
    h('div', { class: 'titlebar' }, h('h2', {}, 'Logical names'),
      h('button', { type: 'button', onclick: () => defineDialog(ctx, remembered.table, null, () => load().catch(() => {})) },
        'Define…')),
    h('p', { class: 'muted' },
      'The shareable logical name tables and their names, read as you: SHOW LOGICAL runs as you, so you see what you would at a terminal. Click a name to see what it translates to, and to change or deassign it.'),
    h('div', { class: 'lnm' }, side, h('div', { class: 'lnm-main' },
      h('form', { class: 'cmdline', role: 'search',
        onsubmit: (ev) => { ev.preventDefault(); remembered.filter = input.value.trim(); load().catch(() => {}); } },
        h('span', { class: 'cmd' }, '$ show logical /table=', tableName, ' '), input,
        h('button', { type: 'submit' }, 'Show')),
      slot)),
  ];
}
