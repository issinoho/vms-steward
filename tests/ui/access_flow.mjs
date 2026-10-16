// access_flow.mjs - the Access history view in a headless DOM, against the dev server on
// the stub platform (tests/ui/run.sh): every source read for a day; over the last 30
// days the stub's SSH logs stop at their time limit, as a node with a crowded
// SSH$ROOT:[VAR] does, and the view says so for that source alone.
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
const { accessView } = await import(process.env.STEWARD_UI_JS + '/access.js');

// Until the view has replaced "Reading…" with what it read.
async function settled(root) {
  for (let i = 0; i < 100; i++) {
    if (root.querySelector('ul.sources') || root.querySelector('.refusal')) return;
    await new Promise((r) => setTimeout(r, 20));
  }
}
const chip = (root, label) => [...root.querySelectorAll('ul.sources li')].find((li) => li.textContent.startsWith(label));

try {
  await api.signIn('STEWARD_ADM', 'admin-pass');
  await api.setPrivileges(['SYSPRV']);
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...[await accessView({ me, touched() {}, refresh() {}, authLost() {} })].flat(Infinity));
  document.body.append(root);
  await settled(root);
  say(root.querySelectorAll('ul.sources li.ok').length === 5 && !root.querySelector('ul.sources li.part'),
    'the last day: every source read in full', root.querySelector('ul.sources')?.outerHTML);

  const form = root.querySelector('form.cmdline');
  const since = form.querySelector('select[aria-label="Since"]');
  since.value = String(30 * 86400);
  root.querySelector('ul.sources').remove();
  form.dispatchEvent(new W.Event('submit', { cancelable: true }));
  await settled(root);
  const ssh = chip(root, 'SSH logs');
  say(ssh && ssh.classList.contains('part') && ssh.textContent.includes('(read in part)'),
    'the last 30 days: the SSH logs marked read in part', ssh && ssh.outerHTML);
  say(root.querySelectorAll('ul.sources li.part').length === 1 && chip(root, 'Accounting')?.classList.contains('ok'),
    'and only that source');
  say(root.textContent.includes('SSH logs: read only in part') && root.textContent.includes('Purging old logs'),
    'with what it means and what fixes it');
  say(!root.querySelector('.refusal'), 'not shown as a refusal');
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
