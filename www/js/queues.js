// queues.js - batch and print queues, read-only (Phase 9, D17).
//
// The queues as SHOW QUEUE lists them, a queue with its jobs as SHOW QUEUE/ALL/FULL,
// and a job as SHOW ENTRY/FULL. It runs as you, and the queue manager decides: a job
// you may not read is listed by entry and status only, "inaccessible", as at a
// terminal.

import { api, ApiError } from './api.js';
import { h } from './dom.js';
import { vmsDate, refusal } from './fmt.js';

const queueHref = (name) => `#/queues/${encodeURIComponent(name)}`;
const jobHref = (entry) => `#/queues/entry/${entry}`;

const WARN = new Set(['stopped', 'stalled', 'paused', 'closed', 'disabled', 'unavailable', 'stopping',
  'refused', 'aborting', 'autostart_inactive', 'stop_pending']);
function tags(list) {
  if (!list || !list.length) return h('span', { class: 'muted' }, '—');
  return h('span', { class: 'tags' }, list.map((s) => h('span', { class: WARN.has(s) ? 'tag warn' : 'tag' }, s.replace(/_/g, ' '))));
}

function back(href, label) { return h('p', {}, h('a', { href }, `← ${label}`)); }

export async function queuesView(ctx) {
  let r;
  try {
    r = await api.queues();
    ctx.touched();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    return [h('div', { class: 'titlebar' }, h('h2', {}, 'Queues')), refusal(err)];
  }
  const rows = r.queues.map((q) => h('tr', {},
    h('td', {}, h('a', { href: queueHref(q.name), class: 'mono' }, q.name)),
    h('td', {}, `${q.generic ? 'generic ' : ''}${q.kind}`),
    h('td', {}, tags(q.status)),
    h('td', { class: 'mono' }, q.node || '—'),
    h('td', { class: 'num' }, String(q.executing)),
    h('td', { class: 'num' }, String(q.pending)),
    h('td', { class: 'num' }, String(q.holding + q.timed)),
    h('td', { class: 'muted' }, q.description)));
  return [
    h('div', { class: 'titlebar' }, h('h2', {}, 'Queues'),
      h('button', { type: 'button', onclick: () => ctx.refresh() }, 'Refresh')),
    h('p', { class: 'muted' }, 'Every batch and output queue, as SHOW QUEUE lists them. Open one to see its jobs.'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'grid queues' },
      h('thead', {}, h('tr', {}, ['Queue', 'Kind', 'Status', 'Node', 'Executing', 'Pending', 'Holding', 'Description'].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 8, class: 'muted' }, 'No queues'))))),
  ];
}

export async function queueView(ctx, name) {
  if (name.startsWith('entry/')) return jobView(ctx, name.slice(6));
  let q;
  try {
    q = await api.queue(name);
    ctx.touched();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    return [back('#/queues', 'Queues'), h('h2', { class: 'mono' }, name), refusal(err)];
  }
  const rows = q.jobs.map((j) => (j.accessible
    ? h('tr', {},
      h('td', {}, h('a', { href: jobHref(j.entry), class: 'mono' }, String(j.entry))),
      h('td', { class: 'mono' }, j.name), h('td', { class: 'mono' }, j.username),
      h('td', {}, tags(j.status)), h('td', {}, j.submitted ? vmsDate(j.submitted) : '—'))
    : h('tr', { class: 'muted' },
      h('td', { class: 'mono' }, String(j.entry)),
      h('td', { colspan: 2 }, '(inaccessible)'),
      h('td', {}, tags(j.status)), h('td', {}, '—'))));
  return [
    back('#/queues', 'Queues'),
    h('div', { class: 'titlebar' }, h('h2', { class: 'mono' }, q.name),
      h('button', { type: 'button', onclick: () => ctx.refresh() }, 'Refresh')),
    q.description ? h('p', { class: 'muted' }, q.description) : null,
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'Kind'), h('dd', {}, `${q.generic ? 'generic ' : ''}${q.kind}`),
      h('dt', {}, 'Status'), h('dd', {}, tags(q.status)),
      h('dt', {}, 'Node'), h('dd', { class: 'mono' }, q.node || '—'),
      h('dt', {}, 'Job limit'), h('dd', {}, q.generic ? '—' : String(q.job_limit)),
      h('dt', {}, 'Jobs'), h('dd', {}, `${q.executing} executing, ${q.pending} pending, ${q.holding} holding, ${q.timed} timed`))),
    h('h3', {}, 'Jobs'),
    h('div', { class: 'tablewrap' }, h('table', { class: 'grid jobs' },
      h('thead', {}, h('tr', {}, ['Entry', 'Job', 'Username', 'Status', 'Submitted'].map((x) => h('th', {}, x)))),
      h('tbody', {}, rows.length ? rows : h('tr', {}, h('td', { colspan: 5, class: 'muted' }, 'No jobs'))))),
    h('p', { class: 'muted small' }, `${q.jobs.length} ${q.jobs.length === 1 ? 'job' : 'jobs'}${q.truncated ? ' (cut short)' : ''}. A job you may not read is shown by entry and status only, as SHOW QUEUE/ALL shows it: the queue's protection decides (SYSPRV reads all).`),
  ];
}

async function jobView(ctx, entry) {
  let j;
  try {
    j = await api.job(entry);
    ctx.touched();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) throw err;
    return [back('#/queues', 'Queues'), h('h2', { class: 'mono' }, `Entry ${entry}`),
      refusal(err, err instanceof ApiError && err.status === 403 ? 'The queue manager lets you read your own jobs, your UIC group\'s where the queue allows it, and anyone\'s with SYSPRV.' : null)];
  }
  return [
    back(queueHref(j.queue), j.queue),
    h('div', { class: 'titlebar' }, h('h2', { class: 'mono' }, `${j.name}  (entry ${j.entry})`),
      h('button', { type: 'button', onclick: () => ctx.refresh() }, 'Refresh')),
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'Username'), h('dd', { class: 'mono' }, j.username),
      h('dt', {}, 'UIC'), h('dd', { class: 'mono' }, j.uic),
      h('dt', {}, 'Account'), h('dd', { class: 'mono' }, j.account || '—'),
      h('dt', {}, 'Queue'), h('dd', {}, h('a', { href: queueHref(j.queue), class: 'mono' }, j.queue)),
      h('dt', {}, 'Status'), h('dd', {}, tags(j.status)),
      h('dt', {}, 'Submitted'), h('dd', {}, j.submitted ? vmsDate(j.submitted) : '—'),
      h('dt', {}, 'After'), h('dd', {}, j.after && j.after !== j.submitted ? vmsDate(j.after) : '—'),
      h('dt', {}, 'Priority'), h('dd', {}, String(j.priority)),
      h('dt', {}, 'Log'), h('dd', { class: 'mono' }, j.log || '—'))),
    h('h3', {}, 'Files'),
    j.files.length ? h('ul', { class: 'files mono' }, j.files.map((f) => h('li', {}, f))) : h('p', { class: 'muted' }, 'None'),
  ];
}
