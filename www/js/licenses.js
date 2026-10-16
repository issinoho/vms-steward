// licenses.js - licences, read-only (Phase 11, D19).
//
// The licences loaded on this node (SHOW LICENSE/FULL), its charge (SHOW
// LICENSE/UNIT_REQUIREMENTS), and the licence database (LICENSE LIST/FULL). OpenVMS has
// no documented service for these, so the commands run in a short-lived process that
// is you (as for logical names), with the privileges you switched on. Any user may
// SHOW LICENSE; the database is as its protection allows, and a refusal is shown.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';

// Fields OpenVMS printed that Steward does not name, as "Label: value".
const others = (l) => (l.other || []).map((o) => `${o.label}: ${o.value}`).join(' · ');

function loadedTable(list) {
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid licenses' },
    h('thead', {}, h('tr', {}, ['Product', 'Producer', 'Units', 'Version', 'Release', 'Terminates',
      'Availability', 'Activity', 'Options'].map((x) => h('th', {}, x)))),
    h('tbody', {}, list.length ? list.map((l) => h('tr', {},
      h('td', { class: 'mono' }, l.product),
      h('td', {}, l.producer),
      h('td', { class: 'mono num' }, l.units),
      h('td', { class: 'mono' }, l.version),
      h('td', { class: 'mono' }, l.release),
      h('td', { class: 'mono' }, l.termination),
      h('td', {}, l.per_core ? h('span', { class: 'tag' }, 'per core') : h('span', { class: 'mono' }, l.availability)),
      h('td', { class: 'mono' }, l.activity),
      h('td', { class: 'small' }, [l.options, others(l)].filter(Boolean).join(' · '))))
      : h('tr', {}, h('td', { colspan: 9, class: 'muted' }, 'No licence is loaded')))));
}

function databaseTable(list) {
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid licenses' },
    h('thead', {}, h('tr', {}, ['Product', 'Producer', 'Issuer', 'Authorization', 'Units', 'Terminates',
      'Status', 'Options', 'Hardware ID', 'Revision', 'Last change'].map((x) => h('th', {}, x)))),
    h('tbody', {}, list.length ? list.map((l) => h('tr', {},
      h('td', { class: 'mono' }, l.product),
      h('td', {}, l.producer),
      h('td', {}, l.issuer),
      h('td', { class: 'mono small' }, l.authorization),
      h('td', { class: 'mono num' }, l.units),
      h('td', { class: 'mono' }, l.termination),
      h('td', {}, l.status),
      h('td', { class: 'small' }, [l.options, others(l)].filter(Boolean).join(' · ')),
      h('td', { class: 'mono small' }, l.hardware_id),
      h('td', { class: 'mono num' }, l.revision),
      h('td', { class: 'small' }, [l.command, l.modified_by, l.modified_on].filter(Boolean).join(' · '))))
      : h('tr', {}, h('td', { colspan: 11, class: 'muted' }, 'The database holds no licence')))));
}

// The database, or OpenVMS's refusal, with what would let you read it.
function database(r, me) {
  const s = r.sources.database;
  if (s.read) {
    const f = r.database_file;
    return [databaseTable(r.database),
      h('p', { class: 'muted small' }, `${r.database.length} in ${f.file || 'the database'}` +
        (f.created ? `, created ${f.created}${f.created_by ? ` by ${f.created_by}` : ''}` : '') + '.')];
  }
  const can = me.authorized_privileges.some((p) => p === 'SYSPRV' || p === 'READALL');
  const on = me.current_privileges.some((p) => p === 'SYSPRV' || p === 'READALL');
  return h('div', { class: 'refusal' },
    h('pre', { class: 'vmsmsg' }, `LICENSE LIST: ${s.vms_message || s.vms_status || 'not read'}`),
    h('p', { class: 'muted' }, on
      ? 'OpenVMS refused the licence database even with your privileges switched on: its protection does not let you read it.'
      : can
        ? h('span', {}, 'The licence database needs SYSPRV or READALL. You hold one: switch it on under ', h('a', { href: '#/account' }, 'My account'), ' to read it.')
        : 'The licence database needs SYSPRV or READALL, which your account does not hold. The licences loaded on this node are above.'));
}

export async function licensesView(ctx) {
  const slot = h('div');
  let first = true;

  async function load() {
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.licenses();
      ctx.touched();
      const loaded = r.sources.loaded.read ? loadedTable(r.loaded)
        : h('div', { class: 'refusal' }, h('pre', { class: 'vmsmsg' }, `SHOW LICENSE: ${r.sources.loaded.vms_message || r.sources.loaded.vms_status || 'not read'}`));
      const charge = r.sources.charge.read
        ? h('pre', { class: 'mono small charge' }, r.charge.lines.join('\n'))
        : h('div', { class: 'refusal' }, h('pre', { class: 'vmsmsg' }, `SHOW LICENSE/UNIT_REQUIREMENTS: ${r.sources.charge.vms_message || r.sources.charge.vms_status || 'not read'}`));
      mount(slot,
        h('h3', {}, `Loaded on ${r.node || 'this node'}`), loaded,
        h('h3', {}, 'Charge'), charge,
        h('h3', {}, 'Licence database'), database(r, ctx.me),
        r.truncated ? h('p', { class: 'muted small' }, 'Cut short: more licences than Steward lists.') : null,
        h('p', { class: 'muted small' }, 'Read-only: register, enable and load licences with LICENSE at a terminal.'));
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
    h('div', { class: 'titlebar' }, h('h2', {}, 'Licences'),
      h('button', { type: 'button', onclick: () => load().catch(() => {}) }, 'Refresh')),
    h('p', { class: 'muted' }, 'The licences loaded on this node (SHOW LICENSE), its charge, and the licence database (LICENSE LIST), as OpenVMS lets you read them.'),
    slot,
  ];
}
