// monitor_flow.mjs - the Monitoring view in a headless DOM, against the dev server on
// the stub platform (tests/ui/run.sh): the first reading, then rates and charts after
// the second; the busiest processes only among those you may see (all of them with
// WORLD); the interval remembered; polling stopped when the page is left.
import { JSDOM } from 'jsdom';
const BASE = process.env.STEWARD_UI_BASE || 'http://127.0.0.1:8088/';
// pretendToBeVisual: otherwise jsdom says the page is hidden, and the view pauses.
const dom = new JSDOM('<!doctype html><body><div id="toasts"></div></body>', { url: BASE, pretendToBeVisual: true });
const W = dom.window;
for (const k of ['window', 'document', 'Node', 'HTMLElement', 'CustomEvent', 'location', 'Event', 'localStorage'])
  globalThis[k] = k === 'window' ? W : W[k];
let cookie = '';
let polls = 0;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  init.headers = { ...(init.headers || {}), ...(cookie ? { Cookie: cookie } : {}), Origin: BASE.slice(0, -1) };
  if (String(url).includes('monitor')) polls++;
  const r = await realFetch(new URL(url, BASE), init);
  const sc = r.headers.get('set-cookie');
  if (sc) cookie = sc.split(';')[0];
  return r;
};
let failed = 0;
const say = (ok, what, extra = '') => { if (!ok) failed++; console.log(ok ? 'ok  ' : 'FAIL', what, ok ? '' : extra); };
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const { api } = await import(process.env.STEWARD_UI_JS + '/api.js');
const { monitorView, stopMonitor } = await import(process.env.STEWARD_UI_JS + '/monitor.js');

async function view() {
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...(await monitorView({ me, touched() {}, refresh() {}, authLost() {} })).flat(Infinity));
  return root;
}
const caption = (t) => t.querySelector('caption').textContent;
const firstCells = (table) => [...table.querySelectorAll('tbody tr td:first-child')].map((t) => t.textContent);

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  let root = await view();
  say(root.textContent.includes('rates need two readings') && !root.querySelector('figure'), 'one reading: no rates yet');
  await wait(1600);   // the second reading comes after a second
  const figs = root.querySelectorAll('figure.chart');
  say(figs.length === 6 && [...figs].map((f) => f.querySelector('.chart-title').textContent).join('|') ===
    'CPU, all CPUs|Process states|Memory|Paging|I/O|Disk operations', 'after two: the six charts', [...figs].map((f) => f.textContent.slice(0, 20)));
  const cpu = figs[0];
  say(cpu.querySelectorAll('.chart-legend li').length === 6 && cpu.querySelectorAll('polygon.area').length === 6 &&
    /User \d+\.\d%/.test(cpu.textContent), 'CPU by mode, stacked, with the latest share', cpu.textContent);
  say(figs[5].querySelectorAll('.chart-legend li').length === 3 && figs[5].textContent.includes('DKA0:'), 'a line for each disk');
  const tables = root.querySelectorAll('table.busiest');
  say(tables.length === 2 && caption(tables[0]) === 'By CPU' && caption(tables[1]) === 'By I/O', 'the busiest, by CPU and by I/O');
  say(firstCells(tables[0]).join() === '_FTA12:_S1' && root.textContent.includes('of the 58 processes on the system are visible to you'),
    'without WORLD, only your own: your MONITOR subprocess', firstCells(tables[0]));
  say(tables[0].querySelector('a').getAttribute('href') === '#/processes/00007521', 'each links to the process');
  const sel = root.querySelector('select[aria-label="Reading interval"]');
  sel.value = '2';
  sel.dispatchEvent(new W.Event('change'));
  say(localStorage.getItem('steward.monitor.interval') === '2', 'the interval chosen is remembered');
  stopMonitor();
  const n = polls;
  await wait(2500);
  say(polls === n, 'leaving the page stops the polls', polls - n);
  await api.signOut();

  await api.signIn('STEWARD_ADM', 'admin-pass');
  await api.setPrivileges(['WORLD']);
  root = await view();
  say(root.querySelector('select').value === '2', 'and offered again');
  await wait(2600);   // the first follow-up after a second, then every 2 s
  const t2 = root.querySelectorAll('table.busiest');
  say(t2.length === 2 && firstCells(t2[0])[0] === 'STEWARD_19301' && firstCells(t2[0]).includes('_FTA12:_S1'),
    'with WORLD, everyone\'s: Steward\'s busy pool process first', t2.length && firstCells(t2[0]));
  stopMonitor();
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
