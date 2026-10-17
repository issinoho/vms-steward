// products_flow.mjs - the Installed products view in a headless DOM, against the dev
// server on the stub platform (tests/ui/run.sh): PCSI refused to an account without
// SYSLCK, with why, and VMSINSTAL's history to anyone; to one authorized for SYSLCK,
// switched on or not (PRODUCT switches it on itself), the installed products
// (filterable) and PCSI's history.
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
const { productsView } = await import(process.env.STEWARD_UI_JS + '/products.js');

async function view() {
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...(await productsView({ me, touched() {}, refresh() {}, authLost() {} })).flat(Infinity));
  return root;
}
const firstCells = (table) => [...table.querySelectorAll('tbody tr td:first-child')].map((t) => t.textContent);

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  let root = await view();
  const ref = root.querySelector('.refusal');
  say(ref && ref.textContent.includes('PRODUCT SHOW: %PCSIUI-E-PRIVCLASS1, operation requires SYSLCK privilege') &&
    ref.textContent.includes('which your account does not hold'), 'PCSI refused, by name, and why', ref && ref.textContent);
  say(root.querySelectorAll('.refusal').length === 1, 'the history\'s identical refusal not repeated');
  let tables = root.querySelectorAll('table.products');
  say(tables.length === 1 && firstCells(tables[0]).join() === '3-MAY-2026,3-MAY-2026,21-APR-2026',
    'VMSINSTAL\'s history to anyone, newest first', tables.length && firstCells(tables[0]));
  say(tables.length && tables[0].querySelector('tr.bad') && tables[0].textContent.includes('failed'), 'a failed installation marked');
  await api.signOut();

  await api.signIn('STEWARD_ADM', 'admin-pass');
  root = await view();
  say(!root.querySelector('.refusal') && root.querySelectorAll('table.products').length === 3,
    'SYSLCK authorized but not switched on: read, as PRODUCT on x86 reads it');
  await api.setPrivileges(['SYSLCK']);
  root = await view();
  tables = root.querySelectorAll('table.products');
  say(!root.querySelector('.refusal') && tables.length === 3, 'with SYSLCK switched on: installed, history and VMSINSTAL');
  say(firstCells(tables[0]).join() === 'WIDGET,LONGPRODUCTNAME,C,SSL3,TCPIP,VMS', 'every installed product', firstCells(tables[0]));
  say(tables[0].textContent.includes('VSI X86VMS TCPIP V6.0-31') && root.textContent.includes('6 products installed by PCSI'),
    'referenced-by lists and the count');
  const details = root.querySelector('details');
  say(details && !details.open && details.querySelector('summary').textContent === 'PCSI history (4)', 'the history folded, with its count');
  const input = root.querySelector('input[aria-label="Filter products"]');
  input.value = 'ssl';
  input.dispatchEvent(new W.Event('input'));
  tables = root.querySelectorAll('table.products');
  say(firstCells(tables[0]).join() === 'SSL3', 'filtered by name', firstCells(tables[0]));
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
