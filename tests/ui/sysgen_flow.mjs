// sysgen_flow.mjs - the System parameters view in a headless DOM, against the dev
// server on the stub platform (tests/ui/run.sh): the list, a string and an internal
// value, a changed value marked, and the filter.
import { JSDOM } from 'jsdom';
const BASE = process.env.STEWARD_UI_BASE || 'http://127.0.0.1:8088/';
const dom = new JSDOM('<!doctype html><body><div id="toasts"></div></body>', { url: BASE });
const W = dom.window;
for (const k of ['window', 'document', 'Node', 'HTMLElement', 'CustomEvent', 'location', 'Event'])
  globalThis[k] = k === 'window' ? W : W[k];
let cookie = '';
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  init.headers = { ...(init.headers || {}), ...(cookie ? { Cookie: cookie } : {}), Origin: BASE.slice(0, -1) };
  const r = await realFetch(new URL(url, BASE), init);
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return r;
};
let failed = 0;
const say = (ok, what, extra = '') => { if (!ok) failed++; console.log(ok ? 'ok  ' : 'FAIL', what, ok ? '' : extra); };
const { api } = await import(process.env.STEWARD_UI_JS + '/api.js');
const { sysgenView } = await import(process.env.STEWARD_UI_JS + '/sysgen.js');
const tick = (ms = 300) => new Promise((r) => setTimeout(r, ms));

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...(await sysgenView({ me, touched() {}, refresh() {}, authLost() {} })).flat(Infinity));
  const names = [...root.querySelectorAll('table.sysgen tbody tr:not(.internal) td:first-child')].map((t) => t.textContent);
  say(names.includes('MAXPROCESSCNT') && names.includes('SCSNODE') && names.length >= 8, 'the parameters', names);
  const scs = [...root.querySelectorAll('table.sysgen tbody tr')].find((r) => r.firstChild.textContent === 'SCSNODE');
  say(scs && scs.children[1].textContent === '"X86VMS"', 'a string parameter, quoted', scs && scs.textContent);
  const mp = [...root.querySelectorAll('table.sysgen tbody tr')].find((r) => r.firstChild.textContent === 'MAXPROCESSCNT');
  say(mp && mp.children[1].classList.contains('changed'), 'a current value off its default, marked');
  say(root.querySelectorAll('tr.internal').length >= 1, 'internal values on their own rows');
  root.querySelector('form.cmdline input').value = 'scs*';
  root.querySelector('form.cmdline').dispatchEvent(new W.Event('submit', { cancelable: true }));
  await tick();
  const after = [...root.querySelectorAll('table.sysgen tbody tr:not(.internal) td:first-child')].map((t) => t.textContent);
  say(after.join() === 'SCSNODE', 'filtered', after);
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
