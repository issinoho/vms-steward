// sysgen.js - system parameters, read-only (Phase 10, D18).
//
// Every parameter as SYSGEN SHOW/ALL prints it: current, default, minimum, maximum,
// unit, and whether it is dynamic. OpenVMS has no service for this, so SYSGEN runs in
// a short-lived process that is you (as for logical names), with the privileges you
// switched on. Any user may run SYSGEN SHOW at a terminal.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';

const remembered = { filter: '' };   // for the way back

// A value as SYSGEN shows it; -1 as a maximum means no limit.
const shown = (v, ascii, isMax) => (ascii ? `"${v}"` : (isMax && v === '-1' ? 'no limit' : v));

export async function sysgenView(ctx) {
  const slot = h('div');
  const input = h('input', { type: 'search', value: remembered.filter, maxlength: 31, spellcheck: 'false',
    autocapitalize: 'characters', 'aria-label': 'Filter', placeholder: '*' });
  let first = true;

  async function load() {
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.sysgen({ filter: remembered.filter });
      ctx.touched();
      const rows = r.parameters.map((p) => {
        const changed = !p.ascii && p.current !== p.default;
        return [
          h('tr', {},
            h('td', { class: 'mono' }, p.name),
            h('td', { class: changed ? 'mono num changed' : 'mono num', title: changed ? 'Not the default' : null }, shown(p.current, p.ascii)),
            h('td', { class: 'mono num muted' }, shown(p.default, p.ascii)),
            h('td', { class: 'mono num muted' }, shown(p.min, p.ascii)),
            h('td', { class: 'mono num muted' }, shown(p.max, p.ascii, true)),
            h('td', {}, p.unit),
            h('td', {}, p.dynamic ? h('span', { class: 'tag' }, 'dynamic') : '')),
          p.internal ? h('tr', { class: 'internal muted small' },
            h('td', { class: 'mono' }, '  internal value'),
            h('td', { class: 'mono num' }, p.internal.current), h('td', { class: 'mono num' }, p.internal.default),
            h('td', { class: 'mono num' }, p.internal.min), h('td', { class: 'mono num' }, shown(p.internal.max, false, true)),
            h('td', {}, p.internal.unit), h('td', {})) : null,
        ];
      });
      mount(slot,
        h('div', { class: 'tablewrap' }, h('table', { class: 'grid sysgen' },
          h('thead', {}, h('tr', {}, ['Parameter', 'Current', 'Default', 'Min.', 'Max.', 'Unit', ''].map((x) => h('th', {}, x)))),
          h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 7, class: 'muted' }, 'No parameter matches'))))),
        h('p', { class: 'muted small' }, `${r.parameters.length} ${r.parameters.length === 1 ? 'parameter' : 'parameters'}${r.truncated ? ' (cut short)' : ''}. A current value that is not the default is marked. Read-only: change parameters with AUTOGEN (MODPARAMS.DAT) or SYSGEN at a terminal.`));
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
    h('div', { class: 'titlebar' }, h('h2', {}, 'System parameters'),
      h('button', { type: 'button', onclick: () => load().catch(() => {}) }, 'Refresh')),
    h('p', { class: 'muted' }, 'The active system parameters, as SYSGEN SHOW/ALL prints them. Filter by name; * and % are wildcards.'),
    h('form', { class: 'cmdline', role: 'search',
      onsubmit: (ev) => { ev.preventDefault(); remembered.filter = input.value.trim(); load().catch(() => {}); } },
      h('span', { class: 'cmd' }, 'SYSGEN> show '), input,
      h('button', { type: 'submit' }, 'Show')),
    slot,
  ];
}
