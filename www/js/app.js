// app.js - the shell: sign-in, navigation and views.
//
// Hash routing (#/account) keeps every URL relative to the page, so nothing needs to
// know where a reverse proxy has mounted the site.

import { api, ApiError } from './api.js';
import { h, mount, toast } from './dom.js';

const app = document.getElementById('app');
let me = null;           // whoami, while signed in
let idleTimer = null;

// Areas of the system, in the order they will arrive (docs/PLAN.md).
const AREAS = [
  { hash: '#/account', label: 'My account', ready: true },
  { hash: '#/users', label: 'Users', phase: 'Phase 2' },
  { hash: '#/identifiers', label: 'Rights identifiers', phase: 'Phase 2' },
  { hash: '#/logicals', label: 'Logical names', phase: 'later' },
  { hash: '#/processes', label: 'Processes', phase: 'later' },
  { hash: '#/queues', label: 'Queues', phase: 'later' },
];

// Messages in OpenVMS form: %FACILITY-S-IDENT, text. Steward's own use the facility
// STEWARD; when OpenVMS refused something, its own message follows on the next line,
// exactly as $GETMSG gave it.
export function vmsMessage(severity, ident, text) {
  return `%STEWARD-${severity}-${ident}, ${text}`;
}

function problemText(err) {
  if (!(err instanceof ApiError)) return vmsMessage('F', 'NOSERVER', 'Steward could not be reached');
  const ident = (err.slug || 'ERROR').replace(/[^a-z0-9]/gi, '').toUpperCase().slice(0, 12);
  const lines = [vmsMessage(err.status >= 500 ? 'F' : 'E', ident, (err.problem.detail || err.message).replace(/\.$/, ''))];
  if (err.vmsMessage) lines.push(err.vmsMessage);
  return lines.join('\n');
}

// Absolute times as OpenVMS writes them: 10-OCT-2026 23:35:41, in the browser's zone.
function vmsDate(epochSeconds) {
  const d = new Date(epochSeconds * 1000);
  const mon = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC'][d.getMonth()];
  const p2 = (n) => String(n).padStart(2, '0');
  return `${d.getDate()}-${mon}-${d.getFullYear()} ${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`;
}

function wordmark() {
  return h('span', { class: 'wordmark', 'aria-label': 'Steward' },
    h('span', { class: 'dollar', 'aria-hidden': 'true' }, '$'), 'steward',
    h('span', { class: 'cursor', 'aria-hidden': 'true' }));
}

// ---------------------------------------------------------------- sign-in

function signInView(note) {
  const user = h('input', { id: 'username', name: 'username', autocomplete: 'username',
    autocapitalize: 'characters', spellcheck: 'false', required: true, maxlength: 12 });
  const pass = h('input', { id: 'password', name: 'password', type: 'password',
    autocomplete: 'current-password', required: true });
  const msg = h('p', { class: 'msg', role: 'alert' }, note || '');
  const button = h('button', { type: 'submit' }, 'Sign in');
  const fail = (text) => { msg.textContent = text; msg.classList.add('error'); };

  const form = h('form', {
    class: 'term',
    onsubmit: async (ev) => {
      ev.preventDefault();
      msg.textContent = '';
      msg.classList.remove('error');
      button.disabled = true;
      try {
        await api.signIn(user.value.trim(), pass.value);
        pass.value = '';
        await start();
      } catch (err) {
        pass.value = '';
        if (err instanceof ApiError && err.slug === 'password-expired') {
          fail(vmsMessage('E', 'PWDEXPIRED', 'your password has expired') +
               '\n-STEWARD-I-CHANGE, change it at an OpenVMS login, then sign in here');
        } else if (err instanceof ApiError && err.status === 401) {
          fail(vmsMessage('E', 'SIGNIN', 'sign-in failed; check the username and password'));
        } else {
          fail(problemText(err));
        }
        pass.focus();
      } finally {
        button.disabled = false;
      }
    },
  },
    h('p', { class: 'banner' },
      h('b', {}, 'Steward'), ' \u2014 OpenVMS system management', h('br'),
      h('span', { class: 'dim' }, 'Sign in with your OpenVMS username and password.')),
    h('div', { class: 'row' }, h('label', { for: 'username' }, 'Username:'), user),
    h('div', { class: 'row' }, h('label', { for: 'password' }, 'Password:'), pass),
    msg, button);

  mount(app, h('main', { class: 'signin-page' },
    h('div', { class: 'bezel' }, form,
      h('div', { class: 'badge', 'aria-hidden': 'true' }, h('span', {}, 'steward'), h('span', { class: 'led' })))));
  user.focus();
}

// ---------------------------------------------------------------- shell

function shell(content) {
  const current = location.hash || '#/account';
  const nav = h('nav', { class: 'sidebar', 'aria-label': 'Areas' },
    wordmark(),
    h('ul', {}, AREAS.map((a) => h('li', {},
      a.ready
        ? h('a', { href: a.hash, 'aria-current': current === a.hash ? 'page' : false }, a.label)
        : h('span', { class: 'soon', title: `Arrives in ${a.phase}` }, a.label, h('small', {}, a.phase))))));

  const top = h('header', { class: 'topbar' },
    h('span', { class: 'prompt' }, '$ show process ', h('b', {}, me.username), ' ', me.uic),
    h('span', { class: 'who' }, h('button', { class: 'ghost', onclick: signOut }, 'Sign out')));

  mount(app, h('div', { class: 'layout' }, nav, h('div', { class: 'main' }, top, h('main', { id: 'view' }, content))));
}

function keys(list, empty, accent) {
  if (!list.length) return h('span', { class: 'muted' }, empty);
  return h('ul', { class: accent ? 'keys accent' : 'keys' }, list.map((x) => h('li', {}, x)));
}

function accountView() {
  const cur = new Set(me.current_privileges);
  const authOnly = me.authorized_privileges.filter((p) => !cur.has(p));
  return [
    h('h2', {}, 'My account'),
    h('p', { class: 'muted' },
      'Everything you do here runs as you: OpenVMS checks your own privileges and rights, exactly as at a terminal.'),
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'Username'), h('dd', {}, me.username),
      h('dt', {}, 'Owner'), h('dd', {}, me.owner || '—'),
      h('dt', {}, 'UIC'), h('dd', { class: 'mono' }, me.uic),
      h('dt', {}, 'Account'), h('dd', {}, me.account || '—'),
      h('dt', {}, 'Session ends'), h('dd', { class: 'mono' }, vmsDate(me.expires_at)))),
    h('h3', {}, 'Privileges in effect'),
    keys(me.current_privileges, 'None', true),
    authOnly.length ? [h('h3', {}, 'Authorized, not enabled'), keys(authOnly, '')] : null,
    h('h3', {}, 'Rights identifiers held'),
    keys(me.identifiers, 'None'),
  ];
}

async function route() {
  if (!me) return;
  const hash = location.hash || '#/account';
  const area = AREAS.find((a) => a.hash === hash && a.ready);
  if (!area) { location.hash = '#/account'; return; }
  // Each view fetches what it shows. That also keeps the server's idle clock and
  // ours in step, since only API calls count as activity there.
  try {
    me = await api.whoami();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { expired('Your session has ended. Sign in again.'); return; }
    toast(problemText(err), 'error');
  }
  armIdle();
  shell(accountView());
}

// ---------------------------------------------------------------- session

// The server ends sessions left idle (no API calls) for idle_timeout seconds. The
// page mirrors that, so it returns to sign-in when it happens rather than failing on
// the next click. Re-armed after API calls only, never on local clicks, which the
// server cannot see.
function armIdle() {
  clearTimeout(idleTimer);
  if (me?.idle_timeout) idleTimer = setTimeout(() => expired('Signed out after inactivity.'), me.idle_timeout * 1000);
}

function expired(note) {
  me = null;
  clearTimeout(idleTimer);
  signInView(note);
}

async function signOut() {
  const me0 = me?.username || '';
  try { await api.signOut(); } catch { /* ending anyway */ }
  me = null;
  clearTimeout(idleTimer);
  toast(vmsMessage('S', 'LOGOUT', `${me0} signed out at ${new Date().toLocaleTimeString()}`));
  signInView();
}

async function start() {
  try {
    me = await api.whoami();
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { signInView(); return; }
    signInView(problemText(err));
    return;
  }
  route();
}

window.addEventListener('hashchange', route);
start();
