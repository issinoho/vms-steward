// fmt.js - formatting shared by the views: OpenVMS-style messages and dates, keycaps.

import { ApiError } from './api.js';
import { h } from './dom.js';

// Messages in OpenVMS form: %FACILITY-S-IDENT, text. Steward's own use the facility
// STEWARD; when OpenVMS refused something, its own message follows on the next line,
// exactly as $GETMSG gave it.
export function vmsMessage(severity, ident, text) {
  return `%STEWARD-${severity}-${ident}, ${text}`;
}

export function problemText(err) {
  if (!(err instanceof ApiError)) return vmsMessage('F', 'NOSERVER', 'Steward could not be reached');
  const ident = (err.slug || 'ERROR').replace(/[^a-z0-9]/gi, '').toUpperCase().slice(0, 12);
  const lines = [vmsMessage(err.status >= 500 ? 'F' : 'E', ident, (err.problem.detail || err.message).replace(/\.$/, ''))];
  if (err.vmsMessage) lines.push(err.vmsMessage);
  return lines.join('\n');
}

const MONTHS = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'];
const p2 = (n) => String(n).padStart(2, '0');

// Absolute times as OpenVMS writes them: 10-OCT-2026 23:35:41, in the browser's zone.
// null (none, never) as AUTHORIZE shows it.
export function vmsDate(epochSeconds, seconds = true) {
  if (epochSeconds === null || epochSeconds === undefined) return '(none)';
  const d = new Date(epochSeconds * 1000);
  const t = `${p2(d.getHours())}:${p2(d.getMinutes())}${seconds ? `:${p2(d.getSeconds())}` : ''}`;
  return `${d.getDate()}-${MONTHS[d.getMonth()]}-${d.getFullYear()} ${t}`;
}

// A list as LK201 keycaps; `lit` marks some of them with the accent edge.
export function keycaps(list, empty = 'None', lit = null) {
  if (!list || !list.length) return h('span', { class: 'muted' }, empty);
  return h('ul', { class: 'keys' }, list.map((x) => h('li', { class: lit && lit.has(x) ? 'on' : '' }, x)));
}

// The inline form of a refusal: the OpenVMS message in a terminal box, and a hint.
export function refusal(err, hint) {
  return h('div', { class: 'refusal' },
    h('pre', { class: 'vmsmsg' }, problemText(err)),
    hint ? h('p', { class: 'muted' }, hint) : null);
}
