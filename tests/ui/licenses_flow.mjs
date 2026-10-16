// licenses_flow.mjs - the Licences view in a headless DOM, against the dev
// server on the stub platform (tests/ui/run.sh): the loaded licences and the charge for
// anyone, the database refused without SYSPRV and listed with it.
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
const { licensesView } = await import(process.env.STEWARD_UI_JS + '/licenses.js');

async function view() {
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...(await licensesView({ me, touched() {}, refresh() {}, authLost() {} })).flat(Infinity));
  return root;
}
const products = (table) => [...table.querySelectorAll('tbody tr td:first-child')].map((t) => t.textContent);

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  let root = await view();
  let tables = root.querySelectorAll('table.licenses');
  say(tables.length === 1 && products(tables[0]).join() === 'BASIC,FMS,OPENVMS-X86-HAOE', 'the loaded licences',
    tables.length && products(tables[0]));
  say([...root.querySelectorAll('h3')].some((x) => x.textContent === 'Loaded on X86VMS'), 'the node');
  say(tables.length && tables[0].querySelectorAll('span.tag').length === 2, 'per core licences marked');
  say((root.querySelector('pre.charge') || {}).textContent?.includes('Units Required: 2'), 'the charge');
  const ref = root.querySelector('.refusal');
  say(ref && ref.textContent.includes('LICENSE LIST: insufficient privilege') && ref.textContent.includes('SYSPRV or READALL'),
    'the database refused, with OpenVMS\'s message and what would let you read it', ref && ref.textContent);
  await api.signOut();

  await api.signIn('STEWARD_ADM', 'admin-pass');
  await api.setPrivileges(['SYSPRV']);
  root = await view();
  tables = root.querySelectorAll('table.licenses');
  say(tables.length === 2 && products(tables[1]).join() === 'BASIC,FMS' && !root.querySelector('.refusal'),
    'with SYSPRV the database is listed', tables.length > 1 && products(tables[1]));
  say(tables.length > 1 && tables[1].textContent.includes('ISV-EXAMPLE-D000000000002') && root.textContent.includes('LMF$LICENSE.LDB'),
    'its authorization numbers and file');
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
