// errorlog_flow.mjs - the Error log view in a headless DOM, against the dev server on
// the stub platform (tests/ui/run.sh): device errors for anyone; the events, crashes
// and OPCOM's log refused without SYSPRV, with what would let you read them; with it,
// the events by range and class, one translated, a crash's summary and listing, and
// OPCOM's messages with and without the hourly stamps.
import { JSDOM } from 'jsdom';
const BASE = process.env.STEWARD_UI_BASE || 'http://127.0.0.1:8088/';
const dom = new JSDOM('<!doctype html><body><div id="toasts"></div></body>', { url: BASE, pretendToBeVisual: true });
const W = dom.window;
for (const k of ['window', 'document', 'Node', 'HTMLElement', 'CustomEvent', 'location', 'Event', 'localStorage'])
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
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
async function until(cond, ms = 4000) {
  for (let t = 0; t < ms; t += 50) { if (cond()) return true; await wait(50); }
  return false;
}
const { api } = await import(process.env.STEWARD_UI_JS + '/api.js');
const { errorlogView } = await import(process.env.STEWARD_UI_JS + '/errorlog.js');
// jsdom has no modal dialogs (as processes_flow.mjs).
W.HTMLDialogElement.prototype.showModal = function () { this.open = true; };
W.HTMLDialogElement.prototype.close = function () { this.open = false; this.dispatchEvent(new W.Event('close')); };
async function confirmDialog(text) {
  const dlg = document.querySelector('dialog');
  if (!dlg) return null;
  const input = dlg.querySelector('input');
  input.value = text;
  dlg.querySelector('form').dispatchEvent(new W.Event('submit', { cancelable: true }));
  await until(() => !document.querySelector('dialog') || !dlg.isConnected || dlg.querySelector('pre.vmsmsg:not([hidden])'));
  return dlg;
}

async function view() {
  const me = await api.whoami();
  const root = document.createElement('div');
  root.append(...(await errorlogView({ me, touched() {}, refresh() {}, authLost() {} })).flat(Infinity));
  return root;
}
const rows = (t) => (t ? [...t.querySelectorAll('tbody tr')] : []);

try {
  await api.signIn('STEWARD_TEST', 'test-pass');
  let root = await view();
  await until(() => root.querySelectorAll('.refusal').length === 3);
  say(root.textContent.includes('DKA100:') && root.textContent.includes('1 device with errors, of 3.'),
    'device errors: anyone\'s, the device with errors listed', root.textContent.slice(0, 400));
  const refusals = [...root.querySelectorAll('.refusal')];
  say(refusals.length === 3 && refusals[0].textContent.includes('%ELV-E-FILOPNERR') &&
    refusals[0].textContent.includes('-RMS-E-PRV, insufficient privilege'),
    'the events refused, with ELV\'s words: PRV', refusals.map((r) => r.textContent.slice(0, 120)));
  say(refusals.every((r) => r.textContent.includes('needs SYSPRV (or the SYSTEM group), which your account does not have')),
    'each refusal says what would let you read it');
  await api.signOut();

  await api.signIn('STEWARD_ADM', 'admin-pass');
  root = await view();
  await until(() => root.querySelectorAll('.refusal').length === 3);
  say(root.querySelector('.refusal a[href="#/account"]') && root.textContent.includes('You hold it: switch it on under My account'),
    'SYSPRV held but off: switch it on (D9)');
  await api.setPrivileges(['SYSPRV']);
  root = await view();
  await until(() => root.querySelector('table.events') && root.querySelector('table.crashes') && root.querySelector('ul.opcom'));
  let ev = root.querySelector('table.events');
  say(rows(ev).length === 6 && rows(ev)[0].textContent.includes('Time Stamp') && rows(ev)[5].textContent.includes('Volume Dismount'),
    'with SYSPRV: the last 30 days, newest first', rows(ev).map((r) => r.textContent.slice(0, 40)));
  say(rows(ev).filter((r) => r.classList.contains('bad')).length === 2, 'bugchecks marked');
  const range = root.querySelector('select[aria-label="Range"]');
  const cls = root.querySelector('select[aria-label="Class"]');
  cls.value = 'BUGCHECKS';
  cls.dispatchEvent(new W.Event('change'));
  ev = root.querySelector('table.events');
  say(rows(ev).length === 2 && rows(ev).every((r) => r.textContent.includes('Bugchecks')), 'filtered by class');
  range.value = '0';
  range.dispatchEvent(new W.Event('change'));
  await until(() => rows(root.querySelector('table.events')).length === 4);
  ev = root.querySelector('table.events');
  say(rows(ev).length === 4, 'everything, still filtered by class: four bugchecks', rows(ev).length);
  const crashBtn = [...ev.querySelectorAll('button.linkish')].find((b) => b.textContent === '1008');
  crashBtn.click();
  await until(() => root.querySelector('table.fields'));
  const fields = root.querySelector('table.fields');
  say(fields && root.textContent.includes('Event 1008: Crash Restart') && fields.querySelector('td.ind1') &&
    fields.querySelector('td.ind1').textContent === 'Current Mode' && fields.textContent.includes('Kernel') &&
    root.textContent.includes('CLUE\'s summary of the crash is under Crashes'),
    'an event translated field by field, bit fields indented; a crash restart points to Crashes', fields && fields.textContent.slice(0, 200));

  const cr = root.querySelector('table.crashes');
  say(rows(cr).length === 2 && rows(cr)[0].textContent.includes('PGFIPLHI') && rows(cr)[1].textContent.includes('INCONSTATE') &&
    rows(cr)[0].textContent.includes('SYS$HUBDRIVER') && !rows(cr)[0].textContent.includes('Link Date'),
    'crashes newest first, with bugcheck, process and module', rows(cr).map((r) => r.textContent.slice(0, 80)));
  rows(cr)[0].querySelector('button').click();
  await until(() => root.querySelector('pre.listing'));
  say(root.querySelector('dl.facts') && root.querySelector('dl.facts').textContent.includes('Bugcheck Type') &&
    root.querySelector('pre.listing').textContent.includes('Stack Pointers:'), 'a crash\'s summary and its whole listing');

  let msgs = root.querySelectorAll('ul.opcom li');
  say(msgs.length === 4 && msgs[0].textContent.includes('Batch queue SYS$BATCH started') && msgs[0].textContent.includes('from SYSTEM on STUB01') &&
    !root.querySelector('ul.opcom').textContent.includes('Logfile time stamp'), 'OPCOM\'s messages, newest first, without the stamps',
    [...msgs].map((m) => m.textContent.slice(0, 60)));
  const filter = root.querySelector('input[aria-label="Filter messages"]');
  filter.value = 'lpd';
  filter.dispatchEvent(new W.Event('input'));
  msgs = root.querySelectorAll('ul.opcom li');
  say(msgs.length === 1 && msgs[0].textContent.includes('-SYSTEM-F-TIMEOUT'), 'filtered, the message whole');
  const stamps = root.querySelector('.cmdline input[type="checkbox"]');
  filter.value = '';
  filter.dispatchEvent(new W.Event('input'));
  stamps.checked = true;
  stamps.dispatchEvent(new W.Event('change'));
  await until(() => root.querySelectorAll('ul.opcom li').length === 6);
  say(root.querySelectorAll('ul.opcom li').length === 6 && root.querySelectorAll('ul.opcom li.muted').length === 2,
    'with the hourly stamps, shown faint');

  // 14b: a new error log, then the renamed one read; crash listings deleted.
  const fileSel = root.querySelector('select[aria-label="File"]');
  say(fileSel && [...fileSel.options].map((o) => o.value).join() === 'ERRLOG.SYS,ERRLOG_20260101_0900.SYS',
    'the file to read: ERRLOG.SYS, or one renamed earlier', fileSel && [...fileSel.options].map((o) => o.value));
  const newBtn = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Start a new error log');
  newBtn.click();
  let dlg = await confirmDialog('errlog');
  say(dlg && dlg.querySelector('pre.vmsmsg:not([hidden])') && dlg.textContent.includes('Type ERRLOG.SYS to confirm'),
    'a new log asks for ERRLOG.SYS typed first', dlg && dlg.textContent.slice(-80));
  dlg = await confirmDialog('errlog.sys');
  await until(() => root.querySelector('select[aria-label="File"]') && /^ERRLOG_\d{8}_\d{4}\.SYS$/.test(root.querySelector('select[aria-label="File"]').value) &&
    root.querySelector('table.events'));
  const sel2 = root.querySelector('select[aria-label="File"]');
  say(sel2 && /^ERRLOG_\d{8}_\d{4}\.SYS$/.test(sel2.value) && rows(root.querySelector('table.events')).length > 0 &&
    !root.textContent.includes('Start a new error log'),
    'ERRLOG.SYS renamed: its events shown under the new name', sel2 && sel2.value);
  sel2.value = 'ERRLOG.SYS';
  sel2.dispatchEvent(new W.Event('change'));
  await until(() => root.textContent.includes('ERRFMT creates it at its next record'));
  say(root.textContent.includes('ERRFMT creates it at its next record'), 'until ERRFMT writes again, no ERRLOG.SYS, and why');

  const boxes = root.querySelectorAll('table.crashes input[type="checkbox"]');
  boxes[1].checked = true;
  boxes[1].dispatchEvent(new W.Event('change'));
  const delBtn = [...root.querySelectorAll('button')].find((b) => b.textContent.startsWith('Delete chosen'));
  say(delBtn && !delBtn.disabled && delBtn.textContent === 'Delete chosen (1)', 'a listing chosen');
  delBtn.click();
  dlg = await confirmDialog('delete');
  await until(() => rows(root.querySelector('table.crashes')).length === 1);
  say(rows(root.querySelector('table.crashes')).length === 1 && rows(root.querySelector('table.crashes'))[0].textContent.includes('PGFIPLHI'),
    'the chosen listing deleted, the other kept');
  root.querySelector('input[type="date"]').value = '2026-12-31';
  [...root.querySelectorAll('button')].find((b) => b.textContent === 'Delete older').click();
  dlg = await confirmDialog('DELETE');
  await until(() => root.textContent.includes('No crash listing'));
  say(root.textContent.includes('No crash listing'), 'and those before a day');
  await api.signOut();
} catch (e) {
  say(false, 'no exception', e.stack);
}
process.exit(failed ? 1 : 0);
