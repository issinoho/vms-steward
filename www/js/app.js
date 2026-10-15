// app.js - the shell: sign-in, navigation and views.
//
// Hash routing (#/account) keeps every URL relative to the page, so nothing needs to
// know where a reverse proxy has mounted the site.

import { api, ApiError } from './api.js';
import { h, mount, toast } from './dom.js';
import { vmsMessage, problemText, vmsDate } from './fmt.js';
import { usersView, userView, identifiersView, identifierView } from './rights.js';
import { changeOwnPassword } from './edit.js';
import { dashboardView, stopDashboard } from './dashboard.js';
import { accessView } from './access.js';
import { logicalsView } from './logicals.js';
import { processesView, processView } from './processes.js';
import { queuesView, queueView } from './queues.js';
import { sysgenView } from './sysgen.js';

const app = document.getElementById('app');
let me = null;           // whoami, while signed in
let idleTimer = null;

// Areas of the system, in the order they will arrive (docs/PLAN.md).
const AREAS = [
  { hash: '#/dashboard', label: 'Dashboard', ready: true },
  { hash: '#/account', label: 'My account', ready: true },
  { hash: '#/users', label: 'Users', ready: true },
  { hash: '#/identifiers', label: 'Rights identifiers', ready: true },
  { hash: '#/access', label: 'Access history', ready: true },
  { hash: '#/logicals', label: 'Logical names', ready: true },
  { hash: '#/processes', label: 'Processes', ready: true },
  { hash: '#/queues', label: 'Queues', ready: true },
  { hash: '#/sysgen', label: 'System parameters', ready: true },
];

// The theme switch (theme.js): Auto, Light, Dark in turn.
const THEME_LABEL = { auto: 'Theme: Auto', light: 'Theme: Light', dark: 'Theme: Dark' };
function themeButton() {
  const b = h('button', { type: 'button', class: 'ghost theme', title: 'Auto follows your browser\'s setting' },
    THEME_LABEL[window.stewardTheme.get()]);
  b.addEventListener('click', () => { b.textContent = THEME_LABEL[window.stewardTheme.next()]; });
  return b;
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
               '\n-STEWARD-I-CHANGE, choose a new one to continue');
          const who = user.value.trim().toUpperCase();
          changeOwnPassword(who, async (next) => {
            await api.signIn(who, next);
            await start();
          }, 'Your password has expired. Enter it once more, then choose a new one.');
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

  mount(app, h('main', { class: 'signin-page' }, themeButton(),
    h('div', { class: 'bezel' }, form,
      h('div', { class: 'badge', 'aria-hidden': 'true' }, h('span', {}, 'steward'), h('span', { class: 'led' })))));
  user.focus();
}

// ---------------------------------------------------------------- shell

function shell(content) {
  const current = '#/' + ((location.hash || '#/dashboard').slice(2).split('/')[0]);
  const nav = h('nav', { class: 'sidebar', 'aria-label': 'Areas' },
    wordmark(),
    h('ul', {}, AREAS.map((a) => h('li', {},
      a.ready
        ? h('a', { href: a.hash, 'aria-current': current === a.hash ? 'page' : false }, a.label)
        : h('span', { class: 'soon', title: `Arrives in ${a.phase}` }, a.label, h('small', {}, a.phase))))));

  const top = h('header', { class: 'topbar' },
    h('span', { class: 'prompt' }, '$ show process ', h('b', {}, me.username), ' ', me.uic),
    h('span', { class: 'who' }, themeButton(), h('button', { class: 'ghost', onclick: signOut }, 'Sign out')));

  mount(app, h('div', { class: 'layout' }, nav, h('div', { class: 'main' }, top, h('main', { id: 'view' }, content))));
}

function keys(list, empty, accent) {
  if (!list.length) return h('span', { class: 'muted' }, empty);
  return h('ul', { class: accent ? 'keys accent' : 'keys' }, list.map((x) => h('li', {}, x)));
}

// Privileges as keys (D9): defaults are always lit; authorized ones can be pressed
// on and off for this session, as SET PROCESS/PRIVILEGE does at a terminal. Each
// press is a request: OpenVMS has the final word, and the page redraws from what
// it reports back.
function privilegeKeys() {
  const defaults = new Set(me.default_privileges);
  const enabled = new Set(me.enabled_privileges);
  const current = new Set(me.current_privileges);

  async function toggle(name, btn) {
    const next = new Set(enabled);
    if (next.has(name)) next.delete(name); else next.add(name);
    btn.disabled = true;
    try {
      me = await api.setPrivileges([...next]);
      armIdle();
      toast(vmsMessage('S', next.has(name) ? 'PRVENA' : 'PRVDIS',
        `${name} ${next.has(name) ? 'enabled' : 'disabled'} for this session`));
      shell(accountView());
    } catch (err) {
      btn.disabled = false;
      if (err instanceof ApiError && err.status === 401) { expired('Your session has ended. Sign in again.'); return; }
      toast(problemText(err), 'error');
    }
  }

  const keysFor = (names, pressable) => h('ul', { class: 'keys' }, names.map((name) => {
    const on = current.has(name);
    if (!pressable) return h('li', { class: on ? 'on' : '' }, name);
    const btn = h('button', {
      type: 'button', class: on ? 'key on' : 'key', 'aria-pressed': on ? 'true' : 'false',
      title: on ? `Switch ${name} off` : `Switch ${name} on for this session`,
    }, name);
    btn.addEventListener('click', () => toggle(name, btn));
    return h('li', { class: 'pressable' }, btn);
  }));

  const optional = me.authorized_privileges.filter((p) => !defaults.has(p));
  return [
    h('h3', {}, 'Default privileges'),
    me.default_privileges.length ? keysFor(me.default_privileges, false) : h('span', { class: 'muted' }, 'None'),
    h('h3', {}, 'Authorized — press to switch on for this session'),
    optional.length
      ? [keysFor(optional, true),
         h('p', { class: 'muted small' }, 'Like SET PROCESS/PRIVILEGE: they stay on until you switch them off or sign out. Each change is audited.')]
      : h('span', { class: 'muted' }, 'None beyond your defaults'),
  ];
}

function accountView() {
  return [
    h('h2', {}, 'My account'),
    h('p', { class: 'muted' },
      'Everything you do here runs as you: OpenVMS checks your own privileges and rights, exactly as at a terminal.'),
    h('div', { class: 'card' }, h('dl', { class: 'facts' },
      h('dt', {}, 'Username'), h('dd', {}, me.username),
      h('dt', {}, 'Owner'), h('dd', {}, me.owner || '\u2014'),
      h('dt', {}, 'UIC'), h('dd', { class: 'mono' }, me.uic),
      h('dt', {}, 'Account'), h('dd', {}, me.account || '\u2014'),
      h('dt', {}, 'Session ends'), h('dd', { class: 'mono' }, vmsDate(me.expires_at)))),
    h('p', {}, h('button', { type: 'button', onclick: () => changeOwnPassword(me.username) }, 'Change password')),
    privilegeKeys(),
    h('h3', {}, 'Rights identifiers held'),
    keys(me.identifiers, 'None'),
  ];
}

// #/area or #/area/NAME. Each view fetches what it shows, which also keeps the
// server's idle clock and ours in step: only API calls count as activity there.
const VIEWS = {
  dashboard: (ctx) => dashboardView(ctx),
  account: async () => {
    me = await api.whoami();
    return accountView();
  },
  users: (ctx, name) => (name ? userView(ctx, name) : usersView(ctx)),
  identifiers: (ctx, name) => (name ? identifierView(ctx, name) : identifiersView(ctx)),
  access: (ctx) => accessView(ctx),
  logicals: (ctx) => logicalsView(ctx),
  processes: (ctx, pid) => (pid ? processView(ctx, pid) : processesView(ctx)),
  queues: (ctx, name) => (name ? queueView(ctx, name) : queuesView(ctx)),
  sysgen: (ctx) => sysgenView(ctx),
};

let routeSeq = 0;

async function route() {
  if (!me) return;
  const [area, ...rest] = (location.hash || '#/dashboard').slice(2).split('/');
  let name = null;
  try { name = rest.length ? decodeURIComponent(rest.join('/')) : null; } catch { name = null; }
  const view = VIEWS[area];
  if (!view || !AREAS.find((a) => a.hash === `#/${area}` && a.ready)) { location.hash = '#/dashboard'; return; }
  stopDashboard();   // its refresh belongs to its page
  const seq = ++routeSeq;
  const ctx = { me, touched: armIdle, refresh: () => route(), authLost: () => expired('Your session has ended. Sign in again.') };
  let content;
  try {
    content = await view(ctx, name);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { expired('Your session has ended. Sign in again.'); return; }
    content = [h('pre', { class: 'vmsmsg' }, problemText(err))];
  }
  if (seq !== routeSeq || !me) return;   // the user moved on while this loaded
  armIdle();
  shell(content);
  window.scrollTo(0, 0);
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
  stopDashboard();
  me = null;
  clearTimeout(idleTimer);
  signInView(note);
}

async function signOut() {
  stopDashboard();
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
window.addEventListener('steward:authlost', () => expired('Your session has ended. Sign in again.'));
start();
