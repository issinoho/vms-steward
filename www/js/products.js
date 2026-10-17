// products.js - installed products, read-only (Phase 12, D20).
//
// What PCSI has installed (PRODUCT SHOW PRODUCT/FULL), its install and remove history
// (PRODUCT SHOW HISTORY/FULL), and VMSINSTAL's own history of installs. PCSI has no
// documented interface, so the commands run in a short-lived process that is you (as
// for logical names), with the privileges you switched on. PRODUCT needs your account
// authorized for SYSLCK, and switches it on itself; a refusal is shown. VMSINSTAL records installs only, never removals: it is history,
// not a list of what is installed now.

import { api, ApiError } from './api.js';
import { h, mount } from './dom.js';
import { refusal } from './fmt.js';

const PRIVCLASS1 = '%X0652800A';   // %PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege

const product = (p) => `${p.producer} ${p.base} ${p.name} ${p.version}`;
const lines = (list) => (list && list.length ? list.map((x) => h('div', {}, x)) : '');

function installedTable(list, filter) {
  const f = filter.trim().toUpperCase();
  const shown = f ? list.filter((p) => product(p).toUpperCase().includes(f)) : list;
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid products' },
    h('thead', {}, h('tr', {}, ['Product', 'Version', 'Producer', 'Base', 'Kit type', 'State', 'Maintenance', 'Referenced by']
      .map((x) => h('th', {}, x)))),
    h('tbody', {}, shown.length ? shown.map((p) => h('tr', {},
      h('td', { class: 'mono' }, p.name),
      h('td', { class: 'mono' }, p.version),
      h('td', {}, p.producer),
      h('td', { class: 'mono' }, p.base),
      h('td', {}, p.kit_type),
      h('td', {}, p.state),
      h('td', { class: 'mono small' }, lines(p.maintenance)),
      h('td', { class: 'mono small' }, lines(p.referenced_by))))
      : h('tr', {}, h('td', { colspan: 8, class: 'muted' }, f ? 'No product matches' : 'PCSI lists no product')))));
}

function historyTable(list) {
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid products' },
    h('thead', {}, h('tr', {}, ['When', 'Operation', 'Product', 'Kit type', 'Validation', 'Error', 'User', 'Remark']
      .map((x) => h('th', {}, x)))),
    h('tbody', {}, list.length ? list.map((p) => h('tr', { class: p.error && p.error !== '0' ? 'bad' : null },
      h('td', { class: 'mono nowrap' }, p.date),
      h('td', {}, p.operation),
      h('td', { class: 'mono' }, product(p)),
      h('td', {}, p.kit_type),
      h('td', { class: 'mono' }, p.validation),
      h('td', { class: 'mono num' }, p.error),
      h('td', { class: 'mono' }, p.user),
      h('td', { class: 'small' }, p.remark)))
      : h('tr', {}, h('td', { colspan: 8, class: 'muted' }, 'PCSI records no history')))));
}

const RESULT = { S: 'succeeded', F: 'failed', NA: 'n/a' };

function vmsinstalTable(list) {
  const newest = [...list].reverse();   // the file is oldest first
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid products' },
    h('thead', {}, h('tr', {}, ['Installed', 'Product', 'Version', 'Result', 'IVP', 'Node', 'Installer', 'Signature']
      .map((x) => h('th', {}, x)))),
    h('tbody', {}, newest.length ? newest.map((v) => h('tr', { class: v.status === 'F' ? 'bad' : null },
      h('td', { class: 'mono nowrap' }, v.date),
      h('td', {}, h('span', { class: 'mono' }, v.mnemonic), v.name ? h('span', { class: 'muted small' }, ` ${v.name}`) : null),
      h('td', { class: 'mono' }, v.version),
      h('td', {}, RESULT[v.status] || v.status),
      h('td', {}, RESULT[v.ivp] || v.ivp),
      h('td', { class: 'mono' }, v.node),
      h('td', { class: 'mono' }, v.installer),
      h('td', { class: 'mono' }, v.signature)))
      : h('tr', {}, h('td', { colspan: 8, class: 'muted' }, 'VMSINSTAL records no installation')))));
}

// PCSI refused: OpenVMS's message, and why when the reason was SYSLCK. PRODUCT switches
// SYSLCK on itself when the account holds it, so there is nothing to switch on here.
function pcsiRefusal(src, me) {
  const msg = h('pre', { class: 'vmsmsg' }, `PRODUCT SHOW: ${src.vms_message || src.vms_status || 'not read'}`);
  if (src.vms_status !== PRIVCLASS1) return h('div', { class: 'refusal' }, msg);
  return h('div', { class: 'refusal' }, msg,
    h('p', { class: 'muted' }, me.authorized_privileges.includes('SYSLCK')
      ? 'PCSI refused although your account holds SYSLCK.'
      : 'PRODUCT SHOW needs SYSLCK, which your account does not hold. VMSINSTAL\'s history, below, is open to anyone.'));
}

const failed = (src, what) => h('div', { class: 'refusal' }, h('pre', { class: 'vmsmsg' }, `${what}: ${src.vms_message || src.vms_status || 'not read'}`));

export async function productsView(ctx) {
  const slot = h('div');
  let first = true;
  let filter = '';

  async function load() {
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.products();
      ctx.touched();
      const src = r.sources;
      let installed;
      if (src.products.read) {
        const box = h('div');
        const draw = () => mount(box, installedTable(r.products, filter),
          h('p', { class: 'muted small' }, `${r.products.length} product${r.products.length === 1 ? '' : 's'} installed by PCSI.`));
        const input = h('input', { type: 'search', class: 'short', value: filter, placeholder: 'Filter', 'aria-label': 'Filter products',
          spellcheck: 'false', oninput: (ev) => { filter = ev.target.value; draw(); } });
        draw();
        installed = [h('div', { class: 'cmdline' }, h('span', { class: 'cmd' }, '$ product show product '), input), box];
      } else {
        installed = pcsiRefusal(src.products, ctx.me);
      }
      // The history repeats the refusal only if it differs from the list's.
      const history = src.history.read
        ? h('details', {}, h('summary', {}, `PCSI history (${r.history.length})`), historyTable(r.history))
        : (!src.products.read && src.history.vms_status === src.products.vms_status ? null : failed(src.history, 'PRODUCT SHOW HISTORY'));
      const vmsinstal = src.vmsinstal.read ? vmsinstalTable(r.vmsinstal) : failed(src.vmsinstal, 'SYS$UPDATE:VMSINSTAL.HISTORY');
      mount(slot,
        h('h3', {}, 'Installed (PCSI)'), installed, history,
        h('h3', {}, 'Installed by VMSINSTAL'),
        h('p', { class: 'muted small' }, 'VMSINSTAL records each installation, never a removal: a product listed here may since have been removed.'),
        vmsinstal,
        r.truncated ? h('p', { class: 'muted small' }, 'Cut short: more entries than Steward lists.') : null,
        h('p', { class: 'muted small' }, 'Read-only: install and remove products with PRODUCT or VMSINSTAL at a terminal.'));
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
    h('div', { class: 'titlebar' }, h('h2', {}, 'Installed products'),
      h('button', { type: 'button', onclick: () => load().catch(() => {}) }, 'Refresh')),
    h('p', { class: 'muted' }, 'What PCSI has installed and its history (PRODUCT SHOW), and VMSINSTAL\'s record of installations, as OpenVMS lets you read them.'),
    slot,
  ];
}
