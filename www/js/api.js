// api.js - the REST client.
//
// URLs are relative to the page ("api/v1/..."), so the site works at a host's root
// or under a reverse-proxy prefix (D7). The session cookie is HttpOnly and never
// visible here. The CSRF token is held in memory only: after a reload, GET
// api/v1/session hands it back.

let csrf = null;

export class ApiError extends Error {
  constructor(status, problem) {
    super(problem?.title || `HTTP ${status}`);
    this.status = status;
    this.problem = problem || {};
  }
  // "%SYSTEM-F-NOPRIV, ..." when OpenVMS refused something.
  get vmsMessage() { return this.problem.vms_message || ''; }
  get slug() { return (this.problem.type || '').split('/').pop(); }
}

async function call(method, path, body, extra) {
  const headers = { Accept: 'application/json', ...(extra || {}) };
  const init = { method, headers, credentials: 'same-origin', cache: 'no-store' };
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  if (method !== 'GET' && csrf) headers['X-Steward-CSRF'] = csrf;
  const res = await fetch(`api/v1/${path}`, init);
  const text = res.status === 204 ? '' : await res.text();
  let doc = null;
  if (text) {
    try { doc = JSON.parse(text); } catch { doc = { title: text.slice(0, 200) }; }
  }
  if (!res.ok) {
    if (res.status === 401) csrf = null;
    throw new ApiError(res.status, doc);
  }
  if (doc && typeof doc.csrf === 'string') csrf = doc.csrf;
  // Something that went wrong after the main work succeeded (e.g. a home directory
  // that could not be created): the caller shows it.
  const warning = res.headers.get('X-Steward-Warning');
  if (warning && doc && typeof doc === 'object') doc.warning = warning;
  return doc;
}

function query(q) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q || {})) if (v !== undefined && v !== null && v !== '') p.set(k, v);
  const s = p.toString();
  return s ? `?${s}` : '';
}

export const api = {
  signIn: (username, password) => call('POST', 'session', { username, password }),
  whoami: () => call('GET', 'session'),
  // The authorized privileges to switch on for this session, on top of the defaults
  // (D9). Returns the updated whoami.
  setPrivileges: (enabled) => call('PUT', 'session/privileges', { enabled }),
  // The system at a glance. background: a refresh, which the server does not count
  // as activity (so the idle timeout still applies to a dashboard left open).
  system: (background) => call('GET', 'system', undefined, background ? { 'X-Steward-Background': '1' } : undefined),
  // Phase 6: access history. q: since, until (seconds since 1970), user, route,
  // outcome, limit.
  access: (q) => call('GET', `access${query(q)}`),
  // Phase 7: logical names (D14).
  logicalTables: () => call('GET', 'logicals/tables'),
  logicals: (q) => call('GET', `logicals${query(q)}`),
  // One name by query, so a name with / in it works too; with every mode it has.
  // mode: the definition at exactly that mode; without it, the outermost.
  logical: (table, name, mode) => call('GET', `logical${query({ table, name, mode })}`),
  // Phase 7b (D15). def: { table, name, mode, attributes, equivalences, replace }.
  // 409 if the name exists at that mode and replace is not set.
  defineLogical: (def) => call('PUT', 'logical', def),
  // At that mode and every outer one, as DEASSIGN; answers { removed: [modes] }.
  deassignLogical: (table, name, mode) => call('DELETE', `logical${query({ table, name, mode })}`),
  // Phase 8: processes (D16). q: { filter }.
  processes: (q) => call('GET', `processes${query(q)}`),
  process: (pid) => call('GET', `processes/${encodeURIComponent(pid)}`),
  // Phase 8b: STOP/ID. 202 { pid, name, username, stopping }; 409 for Steward's own.
  stopProcess: (pid) => call('DELETE', `processes/${encodeURIComponent(pid)}`),
  // Phase 2: users and rights identifiers, read-only. Lists take
  // { filter, after, limit } (and type for identifiers) and return { ..., next }.
  users: (q) => call('GET', `users${query(q)}`),
  user: (name) => call('GET', `users/${encodeURIComponent(name)}`),
  userIdentifiers: (name) => call('GET', `users/${encodeURIComponent(name)}/identifiers`),
  identifiers: (q) => call('GET', `identifiers${query(q)}`),
  identifier: (name) => call('GET', `identifiers/${encodeURIComponent(name)}`),
  holders: (name) => call('GET', `identifiers/${encodeURIComponent(name)}/holders`),
  // Phase 3: changes. OpenVMS decides who may make them; Steward checks the input.
  // patchUser needs the etag from user(): a change made meanwhile gives 412.
  patchUser: (name, changes, etag) => call('PATCH', `users/${encodeURIComponent(name)}`, changes, { 'If-Match': etag }),
  setPassword: (name, password, preExpired) =>
    call('POST', `users/${encodeURIComponent(name)}/password`, { password, pre_expired: !!preExpired }),
  grant: (name, ident, attributes) =>
    call('POST', `users/${encodeURIComponent(name)}/identifiers`, { name: ident, attributes }),
  setHolding: (name, ident, attributes) =>
    call('PUT', `users/${encodeURIComponent(name)}/identifiers/${encodeURIComponent(ident)}`, { attributes }),
  revoke: (name, ident) => call('DELETE', `users/${encodeURIComponent(name)}/identifiers/${encodeURIComponent(ident)}`),
  // Phase 4: create (template DEFAULT) or copy (template a user), and delete (needs the
  // ETag of the record shown).
  createUser: (fields) => call('POST', 'users', fields),
  deleteUser: (name, etag) => call('DELETE', `users/${encodeURIComponent(name)}`, undefined, { 'If-Match': etag }),
  nextUic: (group) => call('GET', `uic/next?group=${encodeURIComponent(group)}`),
  createIdentifier: (fields) => call('POST', 'identifiers', fields),
  modifyIdentifier: (name, fields) => call('PATCH', `identifiers/${encodeURIComponent(name)}`, fields),
  deleteIdentifier: (name) => call('DELETE', `identifiers/${encodeURIComponent(name)}`),
  // Anyone's own password, signed in or not (an expired one cannot sign in).
  changePassword: (username, current, next) => call('POST', 'session/password', { username, current, new: next }),
  signOut: async () => { try { await call('DELETE', 'session'); } finally { csrf = null; } },
};
