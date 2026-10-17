// products.js - installed products, read-only (Phase 12, D20).
//
// What PCSI has installed (PRODUCT SHOW PRODUCT/FULL), its install and remove history
// (PRODUCT SHOW HISTORY/FULL), and VMSINSTAL's own history of installs. PCSI has no
// documented interface, so the commands run in a short-lived process that is you (as
// for logical names), with the privileges you switched on. PRODUCT needs your account
// authorized for SYSLCK, and switches it on itself; a refusal is shown. VMSINSTAL records installs only, never removals: it is history,
// not a list of what is installed now.
//
// Installing and removing (12b, D26): the kits in a directory you name (PRODUCT FIND),
// and an install or removal run as a batch job under your own name, with the
// privileges you switched on; its log is shown as it grows. Steward refuses its own
// product and the operating system; OpenVMS decides the rest.

import { api, ApiError } from './api.js';
import { h, mount, toast } from './dom.js';
import { refusal, vmsMessage } from './fmt.js';
import { dialog, field } from './edit.js';

const LOG_POLL_MS = 2000;
let logTimer = null;   // one job followed at a time; leaving the page stops it
export function stopProductJob() { clearTimeout(logTimer); logTimer = null; }

const PRIVCLASS1 = '%X0652800A';   // %PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege

const product = (p) => `${p.producer} ${p.base} ${p.name} ${p.version}`;
const lines = (list) => (list && list.length ? list.map((x) => h('div', {}, x)) : '');

function installedTable(list, filter, onRemove) {
  const f = filter.trim().toUpperCase();
  const shown = f ? list.filter((p) => product(p).toUpperCase().includes(f)) : list;
  return h('div', { class: 'tablewrap' }, h('table', { class: 'grid products' },
    h('thead', {}, h('tr', {}, ['Product', 'Version', 'Producer', 'Base', 'Kit type', 'State', 'Maintenance', 'Referenced by', '']
      .map((x) => h('th', {}, x)))),
    h('tbody', {}, shown.length ? shown.map((p) => h('tr', {},
      h('td', { class: 'mono' }, p.name),
      h('td', { class: 'mono' }, p.version),
      h('td', {}, p.producer),
      h('td', { class: 'mono' }, p.base),
      h('td', {}, p.kit_type),
      h('td', {}, p.state),
      h('td', { class: 'mono small' }, lines(p.maintenance)),
      h('td', { class: 'mono small' }, lines(p.referenced_by)),
      h('td', {}, p.refused
        ? h('span', { class: 'muted small', title: p.refused }, 'not here')
        : h('button', { type: 'button', class: 'ghost small', onclick: () => onRemove(p) }, 'Remove…'))))
      : h('tr', {}, h('td', { colspan: 9, class: 'muted' }, f ? 'No product matches' : 'PCSI lists no product')))));
}

// ---- 12b: install and remove (D26)

// Follow a submitted job: its log, every two seconds, until its last line.
function followJob(panel, r, what, done) {
  stopProductJob();
  const pre = h('pre', { class: 'listing' }, 'Waiting for the job to start…');
  const state = h('p', { class: 'muted small' }, `Job ${r.entry} on SYS$BATCH, as you; its log is SYS$LOGIN:${r.log}.`);
  mount(panel, h('div', { class: 'panel' },
    h('div', { class: 'titlebar' }, h('h3', {}, what), h('button', { type: 'button', onclick: () => { stopProductJob(); mount(panel); } }, 'Close')),
    state, pre));
  let polls = 0;
  async function poll() {
    try {
      const l = await api.productLog(r.log);
      polls++;
      if (!l.started && polls >= 2) {
        // No log yet: still queued, or gone without one (refused at login: batch
        // access, the login directory).
        let gone = false;
        try { await api.job(r.entry); } catch (err) { gone = err instanceof ApiError && err.status === 404; }
        if (gone) {
          state.textContent = `Job ${r.entry} ended without writing its log: it may not have been able to log in (your account's batch access, its login directory). Its entry in the accounting file says why.`;
          state.className = 'small bad';
          return;
        }
      }
      if (l.started) pre.textContent = l.lines.join('\n') || '(empty so far)';
      if (l.done) {
        state.textContent = l.success ? `Finished: ${l.status}.` : `Failed: ${l.status}. The log above has PRODUCT's messages.`;
        state.className = l.success ? 'small' : 'small bad';
        toast(vmsMessage(l.success ? 'S' : 'E', l.success ? 'DONE' : 'FAILED', `${what}: ${l.status}`), l.success ? 'info' : 'error');
        done();
        return;
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) return;
      state.textContent = `The log could not be read: ${err.message || err}`;
    }
    logTimer = setTimeout(poll, LOG_POLL_MS);
  }
  poll();
}

function jobDialog(title, intro, p, run) {
  const confirm = h('input', { required: true, spellcheck: 'false', placeholder: p.name, class: 'mono' });
  dialog(title, h('div', {}, intro,
    h('p', { class: 'muted small' }, 'It runs as a batch job under your name, with the privileges you switched on: OpenVMS and PCSI decide. PCSI needs CMKRNL, SYSLCK, SYSPRV and TMPMBX switched on. The kit\'s questions take the answers given at its last install, or the producer\'s for a new product.'),
    field(`Type ${p.name} to confirm`, confirm)),
  [{ label: title.split(' ')[0], primary: true, danger: true, run: async () => {
    if (confirm.value.trim().toUpperCase() !== p.name) {
      throw new ApiError(400, { type: '/x/confirm', title: `Type ${p.name} to confirm` });
    }
    await run();
    return true;
  } }]);
}

function removeDialog(p, panel, reload) {
  const refs = p.referenced_by && p.referenced_by.length;
  jobDialog(`Remove ${product(p)}`, h('div', {},
    h('p', {}, `PRODUCT REMOVE ${p.name} /PRODUCER=${p.producer} /BASE_SYSTEM=${p.base}: its files and its entry in the product database go.`),
    refs ? h('p', { class: 'bad' }, `Referenced by: ${p.referenced_by.join(', ')}. PCSI may refuse, or those may stop working.`) : null),
  p, async () => {
    const r = await api.removeProduct({ producer: p.producer, base: p.base, name: p.name });
    followJob(panel, r, `Removing ${p.name}`, reload);
  });
}

function installDialog(k, source, destination, panel, reload) {
  jobDialog(`Install ${product(k)}`, h('p', {},
    `PRODUCT INSTALL ${k.name} /VERSION=${k.version} from ${source}${destination ? `, into ${destination}` : ''}.`),
  k, async () => {
    const body = { producer: k.producer, base: k.base, name: k.name, version: k.version, source };
    if (destination) body.destination = destination;
    const r = await api.installProduct(body);
    followJob(panel, r, `Installing ${k.name} ${k.version}`, reload);
  });
}

function kitsPart(panel, reload) {
  const slot = h('div');
  const src = h('input', { class: 'mono', spellcheck: 'false', placeholder: 'DKA100:[KITS]', 'aria-label': 'Kit directory', required: true });
  const dest = h('input', { class: 'mono short', spellcheck: 'false', placeholder: 'destination (PCSI\'s own)', 'aria-label': 'Destination' });
  async function find() {
    const source = src.value.trim().toUpperCase();
    mount(slot, h('p', { class: 'muted' }, 'Looking…'));
    try {
      const r = await api.productKits(source);
      mount(slot, r.kits.length
        ? h('div', { class: 'tablewrap' }, h('table', { class: 'grid kits' },
          h('thead', {}, h('tr', {}, ['Product', 'Version', 'Producer', 'Base', 'Kit type', 'Format', ''].map((x) => h('th', {}, x)))),
          h('tbody', {}, r.kits.map((k) => h('tr', {},
            h('td', { class: 'mono' }, k.name), h('td', { class: 'mono' }, k.version), h('td', {}, k.producer),
            h('td', { class: 'mono' }, k.base), h('td', {}, k.kit_type), h('td', {}, k.kit_format),
            h('td', {}, k.refused
              ? h('span', { class: 'muted small', title: k.refused }, 'not here')
              : h('button', { type: 'button', class: 'ghost small',
                onclick: () => installDialog(k, r.source, dest.value.trim().toUpperCase(), panel, reload) }, 'Install…')))))))
        : h('p', { class: 'muted' }, r.message || 'No kit there.'),
      r.kits.length && r.message ? h('p', { class: 'muted small' }, r.message) : null);
    } catch (err) {
      mount(slot, refusal(err));
    }
  }
  return [
    h('form', { class: 'cmdline', onsubmit: (ev) => { ev.preventDefault(); find(); } },
      h('span', { class: 'cmd' }, '$ product find * /source='), src, dest, h('button', { type: 'submit' }, 'Find kits')),
    slot,
  ];
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
  const jobPanel = h('div');
  let first = true;
  let filter = '';
  const reload = () => load().catch(() => {});

  async function load() {
    mount(slot, h('p', { class: 'muted' }, 'Reading…'));
    try {
      const r = await api.products();
      ctx.touched();
      const src = r.sources;
      let installed;
      if (src.products.read) {
        const box = h('div');
        const draw = () => mount(box, installedTable(r.products, filter, (p) => removeDialog(p, jobPanel, reload)),
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
        r.truncated ? h('p', { class: 'muted small' }, 'Cut short: more entries than Steward lists.') : null);
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
    jobPanel,
    slot,
    h('h3', {}, 'Install from a kit directory'),
    h('p', { class: 'muted small' }, 'The kits PRODUCT FIND sees in a directory on this node. Steward does not install or remove itself or the operating system: do those at a terminal. VMSINSTAL kits are not handled here.'),
    kitsPart(jobPanel, reload),
  ];
}
