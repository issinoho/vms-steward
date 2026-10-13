// edit.js - making changes (Phase 3): dialogs, the user editor, passwords, grants.
//
// OpenVMS decides who may change what; these forms only gather the change and show
// the answer. A user edit sends only the fields that changed, with the ETag the page
// was drawn from, so a change made meanwhile by someone else is refused (412) rather
// than overwritten. Passwords live only in the form fields and are cleared on close.

import { api, ApiError } from './api.js';
import { h, toast } from './dom.js';
import { vmsMessage, problemText } from './fmt.js';

// ---------------------------------------------------------------- dialogs

// A modal dialog. body: nodes; actions: [{ label, primary, run }] where run() returns
// true to close (or a Promise of it). Escape and Cancel close it. Errors from run()
// show inside the dialog, in OpenVMS form.
export function dialog(title, body, actions) {
  const msg = h('pre', { class: 'vmsmsg', hidden: true });
  const dlg = h('dialog', { class: 'dlg', 'aria-label': title });
  const close = () => dlg.close();   // Escape closes it too; either way 'close' tidies up
  const buttons = actions.map((a) => {
    const b = h('button', { type: a.primary ? 'submit' : 'button', class: a.danger ? 'danger' : (a.primary ? 'primary' : '') }, a.label);
    if (!a.primary) b.addEventListener('click', async () => { if (await a.run()) close(); });   // (none yet)
    return b;
  });
  const primary = actions.find((a) => a.primary);
  const form = h('form', {
    method: 'dialog',
    onsubmit: async (ev) => {
      ev.preventDefault();
      if (!primary) return;
      msg.hidden = true;
      buttons.forEach((b) => { b.disabled = true; });
      try {
        if (await primary.run()) close();
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {   // the session ended: the shell signs out
          close();
          window.dispatchEvent(new CustomEvent('steward:authlost'));
          return;
        }
        msg.textContent = problemText(err);
        msg.hidden = false;
      } finally {
        buttons.forEach((b) => { b.disabled = false; });
      }
    },
  }, h('h2', {}, title), body, msg,
     h('div', { class: 'dlg-actions' }, h('button', { type: 'button', onclick: close }, 'Cancel'), buttons));
  dlg.append(form);
  dlg.addEventListener('close', () => {
    form.querySelectorAll('input[type=password]').forEach((i) => { i.value = ''; });
    dlg.remove();
  });
  document.body.append(dlg);
  dlg.showModal();
  const first = form.querySelector('input, select, textarea');
  if (first) first.focus();
  return dlg;
}

export function field(label, input, hint) {
  const id = `f${Math.random().toString(36).slice(2, 9)}`;
  input.id = id;
  return h('div', { class: 'field' }, h('label', { for: id }, label), input, hint ? h('small', { class: 'muted' }, hint) : null);
}

// LK201-style toggle keys for a set of names; returns { el, value() }.
export function toggles(all, on, title) {
  const state = new Set(on);
  const el = h('ul', { class: 'keys', 'aria-label': title }, all.map((name) => {
    const b = h('button', { type: 'button', class: state.has(name) ? 'key on' : 'key', 'aria-pressed': String(state.has(name)) }, name);
    b.addEventListener('click', () => {
      if (state.has(name)) state.delete(name); else state.add(name);
      b.classList.toggle('on', state.has(name));
      b.setAttribute('aria-pressed', String(state.has(name)));
    });
    return h('li', { class: 'pressable' }, b);
  }));
  return { el, value: () => all.filter((n) => state.has(n)) };
}

// ---------------------------------------------------------------- names (AUTHORIZE's)

export const FLAGS = ['DISCTLY', 'DEFCLI', 'LOCKPWD', 'RESTRICTED', 'DISUSER', 'DISWELCOME',
  'DISNEWMAIL', 'DISMAIL', 'GENPWD', 'PWD_EXPIRED', 'PWD2_EXPIRED', 'AUDIT', 'DISREPORT',
  'DISRECONNECT', 'AUTOLOGIN', 'DISFORCE_PWD_CHANGE', 'CAPTIVE', 'DISIMAGE', 'DISPWDDIC',
  'DISPWDHIS', 'DEFCLSVAL', 'EXTAUTH', 'MIGRATEPWD', 'VMSAUTH', 'DISPWDSYNCH', 'PWDMIX'];
export const PRIVS = ['CMKRNL', 'CMEXEC', 'SYSNAM', 'GRPNAM', 'ALLSPOOL', 'IMPERSONATE', 'DIAGNOSE',
  'LOG_IO', 'GROUP', 'NOACNT', 'PRMCEB', 'PRMMBX', 'PSWAPM', 'ALTPRI', 'SETPRV', 'TMPMBX', 'WORLD',
  'MOUNT', 'OPER', 'EXQUOTA', 'NETMBX', 'VOLPRO', 'PHY_IO', 'BUGCHK', 'PRMGBL', 'SYSGBL', 'PFNMAP',
  'SHMEM', 'SYSPRV', 'BYPASS', 'SYSLCK', 'SHARE', 'UPGRADE', 'DOWNGRADE', 'GRPPRV', 'READALL',
  'IMPORT', 'AUDIT', 'SECURITY'];
export const ATTRIBUTES = ['RESOURCE', 'DYNAMIC', 'NOACCESS', 'SUBSYSTEM', 'IMPERSONATE', 'HOLDER_HIDDEN', 'NAME_HIDDEN'];
const DAYS = ['MON', 'TUE', 'WED', 'THU', 'FRI', 'SAT', 'SUN'];
const KINDS = ['network', 'batch', 'local', 'dialup', 'remote'];
const QUOTAS = [['prio', 'Prio', 31], ['queprio', 'Queprio', 255], ['maxjobs', 'Maxjobs', 65535],
  ['maxacctjobs', 'Maxacctjobs', 65535], ['maxdetach', 'Maxdetach', 65535], ['prclm', 'Prclm', 65535],
  ['biolm', 'BIOlm', 65535], ['diolm', 'DIOlm', 65535], ['astlm', 'ASTlm', 65535], ['tqelm', 'TQElm', 65535],
  ['enqlm', 'Enqlm', 65535], ['fillm', 'Fillm', 65535], ['shrfillm', 'Shrfillm', 65535],
  ['bytlm', 'Bytlm', 4294967295], ['pbytlm', 'Pbytlm', 4294967295], ['jtquota', 'JTquota', 4294967295],
  ['wsdef', 'WSdef', 4294967295], ['wsquo', 'WSquo', 4294967295], ['wsextent', 'WSextent', 4294967295],
  ['pgflquo', 'Pgflquo', 4294967295], ['cpu', 'CPU (10 ms)', 4294967295]];

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// ---------------------------------------------------------------- the user editor

// The edit form for one user. done(updated) is called with the record as it now
// is; it throws a 401 ApiError up.
export function editUser(u, done) {
  const text = (v, max, opts = {}) => h('input', { value: v || '', maxlength: max, spellcheck: 'false', ...opts });
  const f = {
    owner: text(u.owner, 31),
    account: text(u.account, 8, { autocapitalize: 'characters' }),
    cli: text(u.cli, 31), clitables: text(u.clitables, 31),
    default_device: text(u.default_device, 31), default_directory: text(u.default_directory, 63),
    lgicmd: text(u.lgicmd, 63),
  };
  // Dates in the browser's zone, as the rest of the page shows them.
  const day = (t) => { const d = new Date(t * 1000); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };
  const exp = h('input', { type: 'date', value: u.expiration ? day(u.expiration) : '' });
  const life = h('input', { type: 'number', min: 1, max: 9999, value: u.password.lifetime_days ?? '', placeholder: 'none' });
  const minlen = h('input', { type: 'number', min: 0, max: 32, value: u.password.minimum_length });
  const flags = toggles(FLAGS, u.flags, 'Flags');
  const secondary = toggles(DAYS, u.secondary_days, 'Secondary days');
  const auth = toggles(PRIVS, u.authorized_privileges, 'Authorized privileges');
  const def = toggles(PRIVS, u.default_privileges, 'Default privileges');

  // Access hours: click a cell to switch an hour between allowed and refused.
  const hours = {};
  const grid = h('div', { class: 'hourgrid edit' },
    h('span', {}), h('span', { class: 'cap' }, 'Primary'), h('span', { class: 'cap' }, 'Secondary'),
    KINDS.map((k) => {
      hours[k] = { primary: new Set(u.restricted_hours[k].primary), secondary: new Set(u.restricted_hours[k].secondary) };
      const row = (which) => h('span', { class: 'hrs' }, Array.from({ length: 24 }, (_, i) => {
        const cell = h('button', { type: 'button', class: hours[k][which].has(i) ? 'off' : 'on', title: `${k} ${which} ${i}:00` });
        cell.addEventListener('click', () => {
          const s = hours[k][which];
          if (s.has(i)) s.delete(i); else s.add(i);
          cell.className = s.has(i) ? 'off' : 'on';
        });
        return cell;
      }));
      return [h('span', { class: 'kind' }, k), row('primary'), row('secondary')];
    }));

  const quotas = {};
  const qgrid = h('div', { class: 'qedit' }, QUOTAS.map(([k, label, max]) => {
    quotas[k] = h('input', { type: 'number', min: 0, max, value: u.quotas[k] });
    return field(label, quotas[k]);
  }));

  // Only what changed goes to the server: a smaller change, and a clearer audit record.
  function changes() {
    const c = {};
    for (const [k, input] of Object.entries(f)) if (input.value !== (u[k] || '')) c[k] = input.value;
    if (!same(flags.value(), FLAGS.filter((x) => u.flags.includes(x)))) c.flags = flags.value();
    if (exp.value !== (u.expiration ? day(u.expiration) : '')) {
      c.expiration = exp.value ? Math.floor(new Date(`${exp.value}T00:00:00`).getTime() / 1000) : null;
    }
    const pw = {};
    const l = life.value === '' ? null : Number(life.value);
    if (l !== u.password.lifetime_days) pw.lifetime_days = l;
    if (Number(minlen.value) !== u.password.minimum_length) pw.minimum_length = Number(minlen.value);
    if (Object.keys(pw).length) c.password = pw;
    if (!same(secondary.value(), DAYS.filter((d) => u.secondary_days.includes(d)))) c.secondary_days = secondary.value();
    const rh = {};
    for (const k of KINDS) {
      const p = [...hours[k].primary].sort((a, b) => a - b), s = [...hours[k].secondary].sort((a, b) => a - b);
      if (!same(p, u.restricted_hours[k].primary) || !same(s, u.restricted_hours[k].secondary)) rh[k] = { primary: p, secondary: s };
    }
    if (Object.keys(rh).length) c.restricted_hours = rh;
    if (!same(auth.value(), PRIVS.filter((p) => u.authorized_privileges.includes(p)))) c.authorized_privileges = auth.value();
    if (!same(def.value(), PRIVS.filter((p) => u.default_privileges.includes(p)))) c.default_privileges = def.value();
    const q = {};
    for (const [k] of QUOTAS) if (Number(quotas[k].value) !== u.quotas[k]) q[k] = Number(quotas[k].value);
    if (Object.keys(q).length) c.quotas = q;
    return c;
  }

  dialog(`Modify ${u.username}`, h('div', { class: 'editor' },
    h('p', { class: 'muted' }, 'As AUTHORIZE MODIFY. Only what you change is sent, and OpenVMS checks your privileges.'),
    h('div', { class: 'fields' },
      field('Owner', f.owner), field('Account', f.account),
      field('CLI', f.cli), field('Tables', f.clitables),
      field('Device', f.default_device), field('Directory', f.default_directory),
      field('LGICMD', f.lgicmd), field('Expiration', exp, 'empty: none'),
      field('Password lifetime (days)', life, 'empty: none'), field('Password minimum', minlen)),
    h('h3', {}, 'Flags'), flags.el,
    h('h3', {}, 'Secondary days (lit)'), secondary.el,
    h('h3', {}, 'Access hours — lit: allowed; click to change'), grid,
    h('h3', {}, 'Authorized privileges'), auth.el,
    h('h3', {}, 'Default privileges'), def.el,
    h('h3', {}, 'Quotas and limits'), qgrid),
    [{ label: 'Save', primary: true, run: async () => {
      const c = changes();
      if (!Object.keys(c).length) { toast(vmsMessage('I', 'NOCHANGE', 'nothing was changed')); return true; }
      try {
        const updated = await api.patchUser(u.username, c, u.etag);
        toast(vmsMessage('S', 'MDFYMSG', `user record(s) updated: ${Object.keys(c).join(', ')}`));
        done(updated);
        return true;
      } catch (err) {
        if (err instanceof ApiError && err.status === 412) {
          throw new ApiError(412, { ...err.problem, detail: 'The account was changed by someone else after this page loaded. Cancel, reload it, and make your change again.' });
        }
        throw err;
      }
    } }]);
}

// ---------------------------------------------------------------- passwords

function passwordPair() {
  const a = h('input', { type: 'password', autocomplete: 'new-password', required: true, maxlength: 64 });
  const b = h('input', { type: 'password', autocomplete: 'new-password', required: true, maxlength: 64 });
  return { a, b, check() {
    if (a.value !== b.value) throw new ApiError(400, { type: '/x/mismatch', title: 'The two passwords differ' });
    return a.value;
  } };
}

// An administrator sets another user's password (AUTHORIZE MODIFY/PASSWORD).
export function setPassword(u) {
  const p = passwordPair();
  const pre = h('input', { type: 'checkbox', checked: true });
  dialog(`Set ${u.username}'s password`, h('div', {},
    field('New password', p.a), field('Again', p.b),
    h('label', { class: 'check' }, pre, ' Pre-expired: they must change it at their next login (as /PWDEXPIRED)'),
    h('p', { class: 'muted small' }, `OpenVMS requires at least ${u.password.minimum_length} characters for this account.`)),
    [{ label: 'Set password', primary: true, run: async () => {
      await api.setPassword(u.username, p.check(), pre.checked);
      toast(vmsMessage('S', 'PWDSET', `password set for ${u.username}${pre.checked ? ', pre-expired' : ''}`));
      return true;
    } }]);
}

// A user changes their own password. Used signed in (My account) and at sign-in when
// the password has expired; done() is called after success with the new password,
// so the sign-in page can sign straight in with it.
export function changeOwnPassword(username, done, note) {
  const cur = h('input', { type: 'password', autocomplete: 'current-password', required: true, maxlength: 64 });
  const p = passwordPair();
  dialog(`Change ${username}'s password`, h('div', {},
    note ? h('p', { class: 'muted' }, note) : null,
    field('Current password', cur), field('New password', p.a), field('Again', p.b)),
    [{ label: 'Change password', primary: true, run: async () => {
      const next = p.check();
      try {
        await api.changePassword(username, cur.value, next);
      } catch (err) {
        if (err instanceof ApiError && err.status === 401) {   // wrong current password: not a lost session
          throw new ApiError(400, { type: '/x/signin', title: 'The current password is not right' });
        }
        throw err;
      }
      toast(vmsMessage('S', 'PWDCHANGED', 'your password has been changed'));
      if (done) await done(next);
      return true;
    } }]);
}

// ---------------------------------------------------------------- identifiers

// Grant an identifier to a user, choosing holding attributes.
export function grantIdentifier(u, done) {
  const name = h('input', { required: true, maxlength: 31, spellcheck: 'false', autocapitalize: 'characters' });
  const attrs = toggles(ATTRIBUTES, [], 'Attributes');
  dialog(`Grant an identifier to ${u.username}`, h('div', {},
    field('Identifier', name),
    h('h3', {}, 'Attributes of the holding'), attrs.el,
    h('p', { class: 'muted small' }, 'A holding can only have attributes its identifier has.')),
    [{ label: 'Grant', primary: true, run: async () => {
      const r = await api.grant(u.username, name.value.trim(), attrs.value());
      toast(vmsMessage('S', 'GRANTMSG', `identifier ${name.value.trim().toUpperCase()} granted to ${u.username}`));
      done(r);
      return true;
    } }]);
}

export function confirmRevoke(user, ident, done) {
  dialog(`Revoke ${ident}`, h('p', {}, `${user} will no longer hold ${ident}.`),
    [{ label: 'Revoke', primary: true, danger: true, run: async () => {
      await api.revoke(user, ident);
      toast(vmsMessage('S', 'REVOKEMSG', `identifier ${ident} revoked from ${user}`));
      done();
      return true;
    } }]);
}

export function editHolding(user, ident, current, done) {
  const attrs = toggles(ATTRIBUTES, current, 'Attributes');
  dialog(`${user}'s holding of ${ident}`, h('div', {}, attrs.el,
    h('p', { class: 'muted small' }, 'Only attributes the identifier itself has can be set.')),
    [{ label: 'Save', primary: true, run: async () => {
      const r = await api.setHolding(user, ident, attrs.value());
      done(r);
      return true;
    } }]);
}

export function createIdentifier(done) {
  const name = h('input', { required: true, maxlength: 31, spellcheck: 'false', autocapitalize: 'characters' });
  const value = h('input', { maxlength: 10, spellcheck: 'false', placeholder: 'OpenVMS chooses' });
  const attrs = toggles(ATTRIBUTES, [], 'Attributes');
  dialog('New rights identifier', h('div', {},
    field('Name', name, 'A-Z 0-9 _ $, up to 31'), field('Value', value, 'optional: %X8nnnnnnn'),
    h('h3', {}, 'Attributes'), attrs.el),
    [{ label: 'Create', primary: true, run: async () => {
      const body = { name: name.value.trim(), attributes: attrs.value() };
      if (value.value.trim()) body.value = value.value.trim().toUpperCase().replace(/^%X/, '%X');
      const id = await api.createIdentifier(body);
      toast(vmsMessage('S', 'RDBADDMSG', `identifier ${id.name} value ${id.value} added to rights database`));
      done(id);
      return true;
    } }]);
}

export function modifyIdentifier(id, done) {
  const name = h('input', { value: id.name, required: true, maxlength: 31, spellcheck: 'false', autocapitalize: 'characters' });
  const attrs = toggles(ATTRIBUTES, id.attributes, 'Attributes');
  dialog(`Modify ${id.name}`, h('div', {},
    field('Name', name), h('h3', {}, 'Attributes'), attrs.el,
    h('p', { class: 'muted small' }, 'Clearing an attribute here also clears it on every holding (OpenVMS masks holdings by the identifier).')),
    [{ label: 'Save', primary: true, run: async () => {
      const r = await api.modifyIdentifier(id.name, { name: name.value.trim(), attributes: attrs.value() });
      toast(vmsMessage('S', 'RDBMDFYMSG', `identifier ${r.name} modified`));
      done(r);
      return true;
    } }]);
}

// Deleting removes every holding too, so the name must be typed to confirm.
export function deleteIdentifier(id, holders, done) {
  const confirm = h('input', { required: true, spellcheck: 'false', autocapitalize: 'characters', placeholder: id.name });
  dialog(`Delete ${id.name}`, h('div', {},
    h('p', {}, holders
      ? `${holders} holder${holders === 1 ? '' : 's'} will lose it: OpenVMS removes the holdings with the identifier, as AUTHORIZE REMOVE/IDENTIFIER does.`
      : 'Nobody holds it.'),
    field(`Type ${id.name} to confirm`, confirm)),
    [{ label: 'Delete', primary: true, danger: true, run: async () => {
      if (confirm.value.trim().toUpperCase() !== id.name) {
        throw new ApiError(400, { type: '/x/confirm', title: 'Type the identifier\'s name to confirm' });
      }
      await api.deleteIdentifier(id.name);
      toast(vmsMessage('S', 'RDBREMMSG', `identifier ${id.name} removed from rights database`));
      done();
      return true;
    } }]);
}

// ---------------------------------------------------------------- create, copy, delete (Phase 4)

// Create a user from DEFAULT (as AUTHORIZE ADD) or copy one (as AUTHORIZE COPY). The
// dialog starts from the template's own record, so what you see is what the new
// account will get; only what you change is sent as a difference. done(user) gets
// the new account's record.
export async function createUser(templateName, done) {
  let t;
  try {
    t = await api.user(templateName);
  } catch (err) {
    if (err instanceof ApiError && err.status === 401) { window.dispatchEvent(new CustomEvent('steward:authlost')); return; }
    dialog(templateName === 'DEFAULT' ? 'New user' : `Copy ${templateName}`,
      h('pre', { class: 'vmsmsg' }, `${err.problem?.title || err.message}\n${err.vmsMessage || ''}`.trim()), []);
    return;
  }
  const copying = templateName !== 'DEFAULT';
  const name = h('input', { required: true, maxlength: 12, spellcheck: 'false', autocapitalize: 'characters' });
  // A copy starts in the source's group; a new user's group is yours to choose, as
  // AUTHORIZE ADD makes you choose its UIC (DEFAULT's own group is no guide: on the
  // x86 node it was a real user's group, PHASE4.md).
  const group = h('input', { required: true, maxlength: 5, inputmode: 'numeric', placeholder: 'group',
    value: copying ? ((t.uic.match(/^\[(\d+),/) || [])[1] || '') : '' });
  const member = h('input', { required: true, maxlength: 6, inputmode: 'numeric' });
  const owner = h('input', { maxlength: 31, value: copying ? t.owner : '' });
  const account = h('input', { maxlength: 8, value: t.account, spellcheck: 'false' });
  const device = h('input', { maxlength: 31, value: t.default_device || 'SYS$SYSDEVICE:', spellcheck: 'false' });
  const dir = h('input', { maxlength: 63, value: '', spellcheck: 'false' });
  const p = passwordPair();
  const pre = h('input', { type: 'checkbox', checked: true });
  const enabled = h('input', { type: 'checkbox', checked: true });
  const mkdir = h('input', { type: 'checkbox' });
  const copyIds = h('input', { type: 'checkbox' });
  let dirEdited = false;
  dir.addEventListener('input', () => { dirEdited = true; });
  name.addEventListener('input', () => {   // [USERNAME] until the directory is edited
    if (!dirEdited) dir.value = name.value ? `[${name.value.trim().toUpperCase()}]` : '';
  });
  async function suggest() {               // the next free member of the group
    if (!/^[0-7]{1,5}$/.test(group.value.trim())) return;
    try {
      const r = await api.nextUic(group.value.trim());
      const m = r.uic.match(/,(\d+)\]$/);
      if (m) member.value = m[1];
    } catch { /* leave it for the user */ }
  }
  group.addEventListener('change', suggest);
  suggest();

  dialog(copying ? `Copy ${t.username}` : 'New user', h('div', { class: 'editor' },
    h('p', { class: 'muted' }, copying
      ? `As AUTHORIZE COPY: every setting of ${t.username}, with a new name, UIC and password. Its identifiers are copied only if you ask.`
      : 'As AUTHORIZE ADD: the settings of the DEFAULT account, with a new name, UIC and password. Change the rest afterwards with Modify.'),
    h('div', { class: 'fields' },
      field('Username', name, 'A-Z 0-9 _ $, up to 12'),
      h('div', { class: 'field uicpair' },
        h('label', {}, 'UIC (octal)'),
        h('div', { class: 'uicin' }, '[', group, ',', member, ']'),
        h('small', { class: 'muted' }, 'enter the group: the next free member is suggested')),
      field('Owner', owner), field('Account', account),
      field('Device', device), field('Directory', dir, 'follows the username until you edit it'),
      field('Password', p.a, `at least ${t.password.minimum_length} characters`), field('Again', p.b)),
    h('label', { class: 'check' }, pre, ' Pre-expired: they choose their own at first login (as /PWDEXPIRED)'),
    t.flags.includes('DISUSER')
      ? h('label', { class: 'check' }, enabled, ` Can log in: clear the DISUSER flag ${copying ? t.username : 'DEFAULT'} has`)
      : null,
    h('label', { class: 'check' }, mkdir, ' Create the default directory, owned by the new account'),
    copying ? h('label', { class: 'check' }, copyIds, ` Also grant the identifiers ${t.username} holds`) : null),
    [{ label: copying ? 'Copy' : 'Create', primary: true, run: async () => {
      const body = {
        username: name.value.trim(),
        uic: `[${group.value.trim()},${member.value.trim()}]`,
        password: p.check(),
        pre_expired: pre.checked,
        create_directory: mkdir.checked,
      };
      if (copying) { body.template = t.username; body.copy_identifiers = copyIds.checked; }
      if (owner.value !== (copying ? t.owner : '')) body.owner = owner.value;
      if (account.value !== t.account) body.account = account.value;
      if (device.value !== t.default_device) body.default_device = device.value;
      if (dir.value && dir.value !== t.default_directory) body.default_directory = dir.value;
      if (t.flags.includes('DISUSER') && enabled.checked) body.flags = t.flags.filter((f) => f !== 'DISUSER');
      const u = await api.createUser(body);
      toast(vmsMessage('S', copying ? 'COPMSG' : 'ADDMSG', `user ${u.username} ${u.uic} ${copying ? 'copied from ' + t.username : 'added'}`));
      if (u.warning) toast(vmsMessage('W', 'NODIR', u.warning), 'error');
      done(u);
      return true;
    } }]);
}

// Delete a user, as AUTHORIZE REMOVE: the record, its UIC identifier and its holdings.
// Its files and directory stay. The name must be typed to confirm.
export function deleteUser(u, heldCount, done) {
  const confirm = h('input', { required: true, spellcheck: 'false', autocapitalize: 'characters', placeholder: u.username });
  dialog(`Delete ${u.username}`, h('div', {},
    h('p', {}, `The account ${u.username} ${u.uic} is removed from SYSUAF, with its UIC identifier`,
      heldCount ? ` and its ${heldCount} identifier holding${heldCount === 1 ? '' : 's'}` : '',
      ', as AUTHORIZE REMOVE does. Its files and directory are not touched.'),
    field(`Type ${u.username} to confirm`, confirm)),
    [{ label: 'Delete', primary: true, danger: true, run: async () => {
      if (confirm.value.trim().toUpperCase() !== u.username) {
        throw new ApiError(400, { type: '/x/confirm', title: 'Type the username to confirm' });
      }
      await api.deleteUser(u.username, u.etag);
      toast(vmsMessage('S', 'REMMSG', `user ${u.username} removed`));
      done();
      return true;
    } }]);
}
