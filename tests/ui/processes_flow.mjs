// processes_flow.mjs - the Processes view in a headless DOM, against the dev server on
// the stub platform (tests/ui/run.sh): what each user may see, the process page,
// and the refusal for one the viewer may not see.
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
const { processesView, processView } = await import(process.env.STEWARD_UI_JS + '/processes.js');
const ctx = (me) => ({ me, touched() {}, refresh() {}, authLost() { console.log('AUTHLOST'); } });
const render = async (nodes) => {
  const root = document.createElement('div');
  root.append(...(await nodes).flat(Infinity));
  return root;
};
const pids = (root) => [...root.querySelectorAll('table.processes tbody a')].map((a) => a.textContent);

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  let me = await api.whoami();
  let root = await render(processesView(ctx(me)));
  say(pids(root).join() === '00007520,00007521', 'STEWARD_TEST: its own two processes', pids(root));
  root = await render(processView(ctx(me), '00007500'));
  say(/NOPRIV/.test(root.querySelector('pre.vmsmsg')?.textContent || '') && /GROUP switched on/.test(root.textContent),
      'a pool process: NOPRIV, with the hint about GROUP and WORLD', root.textContent.slice(0, 200));
  await api.signOut();

  await api.signIn('STEWARD_ADM', 'admin-pass');
  me = await api.setPrivileges(['WORLD']);
  root = await render(processesView(ctx(me)));
  say(pids(root).length === 7 && root.textContent.includes('STEWARD.EXE') && root.textContent.includes('0 00:00:16.00'),
      'STEWARD_ADM with WORLD: all seven, image names and CPU as SHOW SYSTEM', pids(root));
  root = await render(processView(ctx(me), '00007500'));
  const facts = root.querySelector('dl.facts')?.textContent || '';
  say(facts.includes('STEWARD') && facts.includes('[362,2]') && facts.includes('detached') &&
      root.querySelectorAll('table.grid tbody tr').length === 9 && root.querySelectorAll('ul.keys li').length >= 2,
      'the process page: facts, nine quotas, privileges and rights', facts.slice(0, 200));
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
