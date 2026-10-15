// logicals_flow.mjs - the Logical names view in a headless DOM, against the dev server
// on the stub platform: render, filter, Modify per mode with the no_alias warning, and
// Deassign. Run by tests/ui/run.sh (make ui-test), which needs jsdom (npm) and node.
//
// Added after a browser check found the view broken (a function lost in an edit):
// node --check only proves the files parse.
import { JSDOM } from 'jsdom';
const BASE = process.env.STEWARD_UI_BASE || 'http://127.0.0.1:8088/';
const dom = new JSDOM('<!doctype html><body><div id="toasts"></div></body>', { url: BASE });
const W = dom.window;
for (const k of ['window', 'document', 'Node', 'HTMLElement', 'CustomEvent', 'location', 'Event'])
  globalThis[k] = k === 'window' ? W : W[k];
W.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
W.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new W.Event('close')); };
let cookie = '';
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  init.headers = { ...(init.headers || {}), ...(cookie ? { Cookie: cookie } : {}), Origin: BASE.slice(0, -1) };
  const r = await realFetch(new URL(url, BASE), init);
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return r;
};
const tick = (ms = 300) => new Promise((r) => setTimeout(r, ms));
let failed = 0;
const say = (ok, what, extra = '') => { if (!ok) failed++; console.log(ok ? 'ok  ' : 'FAIL', what, ok ? '' : extra); };
const { api } = await import(process.env.STEWARD_UI_JS + '/api.js');
const { logicalsView } = await import(process.env.STEWARD_UI_JS + '/logicals.js');
await api.signIn('STEWARD_ADM', 'admin-pass');
const me = await api.setPrivileges(['SYSPRV', 'SYSNAM']);
const ctx = { me, touched() {}, refresh() {}, authLost() { console.log('AUTHLOST'); } };
for (const [mode, v] of [['user', 'U'], ['exec', 'E']])
  await api.defineLogical({ table: 'LNM$SYSTEM_TABLE', name: '7B_TEST', mode, equivalences: [{ value: v }], replace: true });

const root = document.createElement('div');
document.body.append(root);
try {
  root.append(...(await logicalsView(ctx)).flat(Infinity));
} catch (e) { say(false, 'view renders', e.stack); process.exit(1); }
await tick();
say(!root.querySelector('pre.vmsmsg') && root.textContent.includes('LNM$SYSTEM_TABLE'), 'the view renders, tables and names',
    root.querySelector('pre.vmsmsg')?.textContent);
const input = root.querySelector('form.cmdline input');
input.value = '7B_TEST';
root.querySelector('form.cmdline').dispatchEvent(new W.Event('submit', { cancelable: true }));
await tick();
const nameBtn = [...root.querySelectorAll('button.linkish')].find((b) => b.textContent === '7B_TEST');
say(!!nameBtn, 'the filter finds 7B_TEST');
nameBtn.click();
await tick();
const buttons = [...root.querySelectorAll('.lnm-actions button')].map((b) => b.textContent);
say(buttons.includes('Modify user…') && buttons.includes('Modify executive…') && buttons.includes('Deassign…'),
    'a Modify button per mode, and Deassign', buttons);
[...root.querySelectorAll('.lnm-actions button')].find((b) => b.textContent === 'Modify executive…').click();
await tick();
let dlg = document.querySelector('dialog');
say(dlg && dlg.querySelector('h2').textContent === 'Modify 7B_TEST (executive mode)', 'the dialog edits the executive-mode definition',
    dlg && dlg.querySelector('h2').textContent);
say(dlg.querySelector('.eqrow input').value === 'E', 'with its own value', dlg.querySelector('.eqrow input').value);
[...dlg.querySelectorAll('button.key')].find((b) => b.textContent === 'no_alias').click();
dlg.querySelector('form').dispatchEvent(new W.Event('submit', { cancelable: true }));
await tick();
const note = dlg.querySelector('p.warn-text');
say(dlg.open && note && !note.hidden && /removes 7B_TEST at user mode/.test(note.textContent),
    'Save warns that the user-mode name goes, and does not save yet', note && note.textContent);
let d = await api.logical('LNM$SYSTEM_TABLE', '7B_TEST');
say(d.modes.join() === 'user,exec', 'nothing changed yet', d.modes);
dlg.querySelector('form').dispatchEvent(new W.Event('submit', { cancelable: true }));
await tick();
d = await api.logical('LNM$SYSTEM_TABLE', '7B_TEST');
say(!dlg.isConnected && d.modes.join() === 'exec' && d.logical.attributes.includes('no_alias'),
    'Save again: executive mode no_alias, the user-mode name gone', [d.modes, d.logical.attributes]);
console.log('toasts:', [...document.querySelectorAll('.toast')].map((t) => t.textContent));
// Deassign through the dialog.
await tick();
const btn2 = [...root.querySelectorAll('button.linkish')].find((b) => b.textContent === '7B_TEST');
btn2.click();
await tick();
[...root.querySelectorAll('.lnm-actions button')].find((b) => b.textContent === 'Deassign…').click();
await tick();
dlg = document.querySelector('dialog');
say(dlg && /removed from LNM\$SYSTEM_TABLE at executive mode/.test(dlg.textContent), 'the deassign dialog names the mode', dlg && dlg.textContent);
dlg.querySelector('form').dispatchEvent(new W.Event('submit', { cancelable: true }));
await tick();
try { await api.logical('LNM$SYSTEM_TABLE', '7B_TEST'); say(false, 'deassigned'); }
catch (e) { say(e.status === 404, 'deassigned', e.status); }
process.exit(failed ? 1 : 0);
