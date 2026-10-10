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

async function call(method, path, body) {
  const headers = { Accept: 'application/json' };
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
  // Phase 2: users and rights identifiers, read-only. Lists take
  // { filter, after, limit } (and type for identifiers) and return { ..., next }.
  users: (q) => call('GET', `users${query(q)}`),
  user: (name) => call('GET', `users/${encodeURIComponent(name)}`),
  userIdentifiers: (name) => call('GET', `users/${encodeURIComponent(name)}/identifiers`),
  identifiers: (q) => call('GET', `identifiers${query(q)}`),
  identifier: (name) => call('GET', `identifiers/${encodeURIComponent(name)}`),
  holders: (name) => call('GET', `identifiers/${encodeURIComponent(name)}/holders`),
  signOut: async () => { try { await call('DELETE', 'session'); } finally { csrf = null; } },
};
