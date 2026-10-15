// queues_flow.mjs - the Queues view in a headless DOM, against the dev server on the
// stub platform (tests/ui/run.sh): the queues, a queue with an inaccessible job, a job
// with its files, and the refusal for a job the viewer may not read.
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
const { queuesView, queueView } = await import(process.env.STEWARD_UI_JS + '/queues.js');
const ctx = (me) => ({ me, touched() {}, refresh() {}, authLost() { console.log('AUTHLOST'); } });
const render = async (nodes) => {
  const root = document.createElement('div');
  root.append(...(await nodes).flat(Infinity));
  return root;
};

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  const me = await api.whoami();
  let root = await render(queuesView(ctx(me)));
  const names = [...root.querySelectorAll('table.queues tbody a')].map((a) => a.textContent);
  say(names.join() === 'SYS$BATCH,X86VMS_BATCH,SYS$PRINT,LPA0_PRINT' && /generic batch/.test(root.textContent) &&
      root.querySelector('.tag.warn')?.textContent === 'stopped', 'the queues, generic ones named, a stopped one marked', names);
  root = await render(queueView(ctx(me), 'X86VMS_BATCH'));
  const rows = [...root.querySelectorAll('table.jobs tbody tr')];
  say(rows.length === 2 && rows.some((r) => /\(inaccessible\)/.test(r.textContent) && /141/.test(r.textContent)) &&
      rows.some((r) => /REPORT/.test(r.textContent) && r.querySelector('a')?.getAttribute('href') === '#/queues/entry/272'),
      'a queue: another group\'s job inaccessible, the group\'s linked', rows.map((r) => r.textContent));
  root = await render(queueView(ctx(me), 'entry/269'));
  say(/NIGHTLY/.test(root.textContent) && root.querySelector('ul.files li')?.textContent.includes('NIGHTLY.COM') &&
      /holding/.test(root.textContent), 'a job: name, status and files');
  root = await render(queueView(ctx(me), 'entry/141'));
  say(/NOPRIV/.test(root.querySelector('pre.vmsmsg')?.textContent || '') && /SYSPRV reads|anyone's with SYSPRV/.test(root.textContent),
      'an inaccessible job: NOPRIV, with the hint');
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
