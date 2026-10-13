const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { db, databasePath } = require('./db');

const scrypt = promisify(crypto.scrypt);
const root = path.resolve(__dirname);
const port = Number(process.env.PORT || 4173);
const host = process.env.HOST || '127.0.0.1';
const secureCookie = process.env.NODE_ENV === 'production';
const sessionLifetimeMs = 1000 * 60 * 60 * 24 * 14;
const contentTypes = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8' };
const blankState = { leads: [], activities: [], tasks: [], conversations: [], deals: [], calls: [], meetings: [], workflows: [], campaigns: [], payments: [], members: [], activitiesLog: [] };
const limits = new Map();
const insertSession = db.prepare('INSERT INTO sessions (token_hash,user_id,workspace_id,expires_at,created_at) VALUES (?,?,?,?,?)');
const insertAudit = db.prepare('INSERT INTO audit_events (id,workspace_id,actor_user_id,action,entity_type,entity_id,details,created_at) VALUES (?,?,?,?,?,?,?,?)');
const selectSession = db.prepare(`SELECT u.id AS user_id,u.email,u.display_name,w.id AS workspace_id,w.name AS workspace_name,w.currency,w.timezone,w.website,w.description,m.role
  FROM sessions s JOIN users u ON u.id=s.user_id JOIN workspaces w ON w.id=s.workspace_id
  JOIN memberships m ON m.user_id=u.id AND m.workspace_id=w.id AND m.status='active'
  WHERE s.token_hash=? AND s.expires_at>?`);

function json(res, status, body, extraHeaders = {}) {
  const data = JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', ...extraHeaders });
  res.end(data);
}

function cookies(req) {
  return Object.fromEntries((req.headers.cookie || '').split(';').map(value => value.trim()).filter(Boolean).map(value => {
    const split = value.indexOf('=');
    return split < 0 ? [value, ''] : [value.slice(0, split), decodeURIComponent(value.slice(split + 1))];
  }));
}

function rateLimit(req, key, maximum = 12, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const k = `${req.socket.remoteAddress}:${key}`;
  const item = limits.get(k);
  if (!item || item.until < now) { limits.set(k, { count: 1, until: now + windowMs }); return true; }
  item.count += 1;
  return item.count <= maximum;
}

async function readJson(req, maxBytes = 1024 * 1024) {
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > maxBytes) { const error = new Error('Request body is too large.'); error.status = 413; throw error; }
  }
  try { return body ? JSON.parse(body) : {}; }
  catch { const error = new Error('Request body must be valid JSON.'); error.status = 400; throw error; }
}

function originIsAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return false;
  const expected = process.env.PUBLIC_ORIGIN || `${secureCookie ? 'https' : 'http'}://${req.headers.host}`;
  try { return new URL(origin).origin === new URL(expected).origin; } catch { return false; }
}

function sessionCookie(token) {
  return `leadloop_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(sessionLifetimeMs / 1000)}${secureCookie ? '; Secure' : ''}`;
}

function clearSessionCookie() {
  return `leadloop_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secureCookie ? '; Secure' : ''}`;
}

function publicSession(row) {
  return { user: { id: row.user_id, email: row.email, name: row.display_name }, workspace: { id: row.workspace_id, name: row.workspace_name, currency: row.currency, timezone: row.timezone, website: row.website, description: row.description }, role: row.role };
}

function currentSession(req) {
  const token = cookies(req).leadloop_session;
  if (!token || token.length > 200) return null;
  return selectSession.get(crypto.createHash('sha256').update(token).digest('hex'), new Date().toISOString()) || null;
}

async function createSession(userId, workspaceId) {
  db.prepare('DELETE FROM sessions WHERE expires_at <= ?').run(new Date().toISOString());
  const token = crypto.randomBytes(32).toString('base64url');
  const now = new Date();
  insertSession.run(crypto.createHash('sha256').update(token).digest('hex'), userId, workspaceId, new Date(now.getTime() + sessionLifetimeMs).toISOString(), now.toISOString());
  return token;
}

function respondWithSession(res, row, token, status = 200) {
  return json(res, status, publicSession(row), { 'Set-Cookie': sessionCookie(token) });
}

function audit(session, action, entityType, entityId, details = {}) {
  insertAudit.run(crypto.randomUUID(), session.workspace_id, session.user_id, action, entityType, String(entityId), JSON.stringify(details), new Date().toISOString());
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  return value;
}

async function handleApi(req, res, url) {
  const pathname = url.pathname;
  if (req.method === 'GET' && pathname === '/api/health') return json(res, 200, { status: 'ok', storage: 'sqlite' });
  if (req.method === 'GET' && pathname === '/api/session') {
    const session = currentSession(req);
    return json(res, 200, { session: session ? publicSession(session) : null });
  }

  const writes = !['GET', 'HEAD', 'OPTIONS'].includes(req.method);
  if (writes && !originIsAllowed(req)) return json(res, 403, { error: 'Request origin was not allowed.' });

  if (req.method === 'POST' && pathname === '/api/auth/signup') {
    if (!rateLimit(req, 'signup', 6)) return json(res, 429, { error: 'Too many sign-up attempts. Try again later.' });
    const body = await readJson(req, 16 * 1024);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    const displayName = String(body.name || '').trim().slice(0, 100) || email.split('@')[0];
    const workspaceName = String(body.workspaceName || '').trim().slice(0, 100);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json(res, 400, { error: 'Enter a valid work email address.' });
    if (password.length < 12 || Buffer.byteLength(password) > 1024) return json(res, 400, { error: 'Use a password between 12 and 128 characters.' });
    if (password.length > 128) return json(res, 400, { error: 'Use a password between 12 and 128 characters.' });
    if (!workspaceName) return json(res, 400, { error: 'Enter a workspace name.' });
    if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return json(res, 409, { error: 'An account already uses that email. Sign in instead.' });
    const now = new Date().toISOString();
    const userId = crypto.randomUUID();
    const workspaceId = crypto.randomUUID();
    const salt = crypto.randomBytes(16).toString('hex');
    const passwordHash = (await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 })).toString('hex');
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare('INSERT INTO users (id,email,display_name,password_salt,password_hash,created_at) VALUES (?,?,?,?,?,?)').run(userId, email, displayName, salt, passwordHash, now);
      db.prepare('INSERT INTO workspaces (id,name,created_at) VALUES (?,?,?)').run(workspaceId, workspaceName, now);
      db.prepare('INSERT INTO memberships (workspace_id,user_id,role,status,created_at) VALUES (?,?,\'owner\',\'active\',?)').run(workspaceId, userId, now);
      db.prepare('INSERT INTO workspace_data (workspace_id,payload,updated_at) VALUES (?,?,?)').run(workspaceId, JSON.stringify(blankState), now);
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); if (error.code === 'ERR_SQLITE_CONSTRAINT_UNIQUE') return json(res, 409, { error: 'An account already uses that email. Sign in instead.' }); throw error; }
    const token = await createSession(userId, workspaceId);
    const row = selectSession.get(crypto.createHash('sha256').update(token).digest('hex'), new Date().toISOString());
    return respondWithSession(res, row, token, 201);
  }

  if (req.method === 'POST' && pathname === '/api/auth/login') {
    if (!rateLimit(req, 'login', 12)) return json(res, 429, { error: 'Too many sign-in attempts. Try again later.' });
    const body = await readJson(req, 16 * 1024);
    const email = String(body.email || '').trim().toLowerCase();
    const password = String(body.password || '');
    if (!email || !password || password.length > 128) return json(res, 400, { error: 'Enter your email and password.' });
    const user = db.prepare('SELECT id,email,password_salt,password_hash FROM users WHERE email=?').get(email);
    const salt = user?.password_salt || 'leadloop-fixed-dummy-salt';
    const actual = await scrypt(password, salt, 64, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
    const expected = Buffer.from(user?.password_hash || '0'.repeat(128), 'hex');
    if (!user || expected.length !== actual.length || !crypto.timingSafeEqual(actual, expected)) return json(res, 401, { error: 'Email or password was not recognized.' });
    const membership = db.prepare(`SELECT workspace_id FROM memberships WHERE user_id=? AND status='active' ORDER BY CASE role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,created_at LIMIT 1`).get(user.id);
    if (!membership) return json(res, 403, { error: 'This account has no active workspace membership.' });
    const token = await createSession(user.id, membership.workspace_id);
    const row = selectSession.get(crypto.createHash('sha256').update(token).digest('hex'), new Date().toISOString());
    return respondWithSession(res, row, token);
  }

  if (req.method === 'POST' && pathname === '/api/auth/logout') {
    const token = cookies(req).leadloop_session;
    if (token) db.prepare('DELETE FROM sessions WHERE token_hash=?').run(crypto.createHash('sha256').update(token).digest('hex'));
    return json(res, 200, { ok: true }, { 'Set-Cookie': clearSessionCookie() });
  }

  const session = currentSession(req);
  if (req.method === 'PATCH' && pathname === '/api/workspace') {
    if (!session) return json(res, 401, { error: 'Sign in to update workspace settings.' });
    if (!['owner', 'admin'].includes(session.role)) return json(res, 403, { error: 'Only the workspace owner or an admin can change workspace settings.' });
    const body = await readJson(req, 16 * 1024);
    const name = String(body.name || '').trim();
    const currency = String(body.currency || '').toUpperCase();
    const timezone = String(body.timezone || 'UTC');
    const website = String(body.website || '').trim();
    const description = String(body.description || '').trim();
    if (!name || name.length > 100) return json(res, 400, { error: 'Workspace name is required and must be under 100 characters.' });
    if (!['USD', 'EUR', 'INR', 'GBP'].includes(currency)) return json(res, 400, { error: 'Choose a supported workspace currency.' });
    if (timezone.length > 100) return json(res, 400, { error: 'Choose a valid workspace time zone.' });
    try { new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(); } catch { return json(res, 400, { error: 'Choose a valid workspace time zone.' }); }
    if (website.length > 200 || description.length > 1000) return json(res, 400, { error: 'Website or description exceeds the allowed length.' });
    if (website && !/^https?:\/\//i.test(website)) return json(res, 400, { error: 'Include https:// in the workspace website.' });
    db.prepare('UPDATE workspaces SET name=?,currency=?,timezone=?,website=?,description=? WHERE id=?').run(name, currency, timezone, website, description, session.workspace_id);
    audit(session, 'workspace.settings_updated', 'workspace', session.workspace_id, { fields: ['name', 'currency', 'timezone', 'website', 'description'] });
    const token = cookies(req).leadloop_session;
    const row = selectSession.get(crypto.createHash('sha256').update(token).digest('hex'), new Date().toISOString());
    return json(res, 200, { session: publicSession(row) });
  }
  if (req.method === 'GET' && pathname === '/api/members') {
    if (!session) return json(res, 401, { error: 'Sign in to view workspace members.' });
    const members = db.prepare(`SELECT u.id AS userId,u.display_name AS name,u.email,m.role,m.status,m.created_at AS createdAt
      FROM memberships m JOIN users u ON u.id=m.user_id WHERE m.workspace_id=? ORDER BY CASE m.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 WHEN 'manager' THEN 2 ELSE 3 END,m.created_at`).all(session.workspace_id);
    const invitations = db.prepare(`SELECT id,email,role,status,created_at AS createdAt FROM invitations WHERE workspace_id=? ORDER BY created_at DESC`).all(session.workspace_id);
    return json(res, 200, { members, invitations });
  }
  if (req.method === 'GET' && pathname === '/api/audit') {
    if (!session) return json(res, 401, { error: 'Sign in to view workspace audit history.' });
    if (!['owner', 'admin'].includes(session.role)) return json(res, 403, { error: 'Only workspace owners and admins can view administrative audit history.' });
    const events = db.prepare(`SELECT a.id,a.action,a.entity_type AS entityType,a.entity_id AS entityId,a.details,a.created_at AS createdAt,u.display_name AS actor
      FROM audit_events a JOIN users u ON u.id=a.actor_user_id WHERE a.workspace_id=? ORDER BY a.created_at DESC LIMIT 100`).all(session.workspace_id).map(event => ({ ...event, details: JSON.parse(event.details) }));
    return json(res, 200, { events });
  }
  const memberRoute = pathname.match(/^\/api\/members\/([0-9a-f-]{36})$/i);
  if (req.method === 'PATCH' && memberRoute) {
    if (!session) return json(res, 401, { error: 'Sign in to update workspace members.' });
    if (!['owner', 'admin'].includes(session.role)) return json(res, 403, { error: 'Only the owner or an admin can update member roles.' });
    const body = await readJson(req, 16 * 1024);
    const role = String(body.role || '').toLowerCase();
    if (!['admin', 'manager', 'agent'].includes(role)) return json(res, 400, { error: 'Choose admin, manager, or agent.' });
    const member = db.prepare('SELECT role FROM memberships WHERE workspace_id=? AND user_id=? AND status=\'active\'').get(session.workspace_id, memberRoute[1]);
    if (!member) return json(res, 404, { error: 'Workspace member was not found.' });
    if (member.role === 'owner') return json(res, 403, { error: 'The workspace owner role cannot be changed here.' });
    db.prepare('UPDATE memberships SET role=? WHERE workspace_id=? AND user_id=?').run(role, session.workspace_id, memberRoute[1]);
    audit(session, 'membership.role_changed', 'membership', memberRoute[1], { previousRole: member.role, role });
    return json(res, 200, { ok: true, role });
  }
  if (req.method === 'GET' && pathname === '/api/state') {
    if (!session) return json(res, 401, { error: 'Sign in to access a workspace.' });
    const row = db.prepare('SELECT payload FROM workspace_data WHERE workspace_id=?').get(session.workspace_id);
    return json(res, 200, { data: row ? JSON.parse(row.payload) : blankState, updatedAt: db.prepare('SELECT updated_at FROM workspace_data WHERE workspace_id=?').get(session.workspace_id)?.updated_at || null });
  }
  if (req.method === 'PUT' && pathname === '/api/state') {
    if (!session) return json(res, 401, { error: 'Sign in to access a workspace.' });
    if (!['owner', 'admin', 'manager'].includes(session.role)) return json(res, 403, { error: 'Your workspace role cannot edit shared records.' });
    const body = await readJson(req, 2 * 1024 * 1024);
    if (!body.data || typeof body.data !== 'object' || Array.isArray(body.data)) return json(res, 400, { error: 'Workspace data must be an object.' });
    const allowed = new Set(Object.keys(blankState));
    const data = {};
    for (const [key, value] of Object.entries(body.data)) {
      if (!allowed.has(key) || !Array.isArray(value) || value.length > 10000) return json(res, 400, { error: `Invalid workspace data collection: ${key}` });
      data[key] = value;
    }
    for (const key of allowed) if (!(key in data)) data[key] = [];
    const currentRow = db.prepare('SELECT payload FROM workspace_data WHERE workspace_id=?').get(session.workspace_id);
    const currentData = currentRow ? JSON.parse(currentRow.payload) : blankState;
    const oldPaid = (currentData.payments || []).filter(payment => payment.status === 'Paid');
    for (const previous of oldPaid) {
      const next = data.payments.find(payment => String(payment.id) === String(previous.id));
      if (!next || JSON.stringify(canonical(next)) !== JSON.stringify(canonical(previous))) {
        return json(res, 409, { error: 'Confirmed payment records are immutable in this prototype. Use an audited correction workflow.' });
      }
    }
    const payload = JSON.stringify(data);
    if (Buffer.byteLength(payload) > 2 * 1024 * 1024) return json(res, 413, { error: 'Workspace data is too large.' });
    const updatedAt = new Date().toISOString();
    const newPaid = data.payments.filter(payment => payment.status === 'Paid' && !(currentData.payments || []).some(previous => String(previous.id) === String(payment.id) && previous.status === 'Paid'));
    db.exec('BEGIN IMMEDIATE');
    try {
      db.prepare(`INSERT INTO workspace_data (workspace_id,payload,updated_at) VALUES (?,?,?)
        ON CONFLICT(workspace_id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`).run(session.workspace_id, payload, updatedAt);
      for (const payment of newPaid) audit(session, 'payment.manual_confirmation', 'payment', payment.id, { amount: payment.amount, currency: payment.currency, reference: payment.reference || null });
      db.exec('COMMIT');
    } catch (error) { db.exec('ROLLBACK'); throw error; }
    return json(res, 200, { ok: true, updatedAt });
  }

  if (req.method === 'POST' && pathname === '/api/invitations') {
    if (!session) return json(res, 401, { error: 'Sign in to manage workspace invitations.' });
    if (!['owner', 'admin'].includes(session.role)) return json(res, 403, { error: 'Only a workspace owner or admin can invite teammates.' });
    const body = await readJson(req, 16 * 1024);
    const email = String(body.email || '').trim().toLowerCase();
    const role = String(body.role || 'agent').toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) return json(res, 400, { error: 'Enter a valid email address.' });
    if (!['admin', 'manager', 'agent'].includes(role)) return json(res, 400, { error: 'Choose an available team role.' });
    const exists = db.prepare('SELECT 1 FROM memberships WHERE workspace_id=? AND user_id IN (SELECT id FROM users WHERE email=?) AND status=\'active\'').get(session.workspace_id, email);
    if (exists) return json(res, 409, { error: 'This person is already a workspace member.' });
    const invitation = { id: crypto.randomUUID(), workspaceId: session.workspace_id, email, role, invitedBy: session.user_id, createdAt: new Date().toISOString() };
    db.prepare(`INSERT INTO invitations (id,workspace_id,email,role,invited_by,status,created_at) VALUES (?,?,?,?,?,'pending',?)
      ON CONFLICT(workspace_id,email) DO UPDATE SET role=excluded.role,status='pending',invited_by=excluded.invited_by,created_at=excluded.created_at`).run(invitation.id, invitation.workspaceId, invitation.email, invitation.role, invitation.invitedBy, invitation.createdAt);
    audit(session, 'membership.invitation_created', 'invitation', invitation.id, { email, role });
    return json(res, 201, { invitation: { email, role, status: 'pending', createdAt: invitation.createdAt }, delivery: 'not_configured' });
  }

  return json(res, 404, { error: 'API route not found.' });
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return await handleApi(req, res, url);
    if (!['GET', 'HEAD'].includes(req.method)) return json(res, 405, { error: 'Method not allowed.' });
    let pathname;
    try { pathname = decodeURIComponent(url.pathname); } catch { return res.writeHead(400).end('Bad request'); }
    const requested = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
    const file = path.resolve(root, requested);
    if (!file.startsWith(root + path.sep) && file !== path.join(root, 'index.html')) return res.writeHead(403).end('Forbidden');
    fs.readFile(file, (error, contents) => {
      if (error) return res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('Not found');
      res.writeHead(200, { 'Content-Type': contentTypes[path.extname(file)] || 'application/octet-stream', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'strict-origin-when-cross-origin', 'X-Frame-Options': 'SAMEORIGIN', 'Content-Security-Policy': "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'" });
      if (req.method === 'HEAD') return res.end();
      res.end(contents);
    });
  } catch (error) {
    const status = Number.isInteger(error.status) ? error.status : 500;
    if (status >= 500) console.error('Leadloop request failed:', error.message);
    json(res, status, { error: status >= 500 ? 'The request could not be completed.' : error.message });
  }
});

server.listen(port, host, () => {
  console.log(`Leadloop available at http://${host}:${port}`);
  console.log(`Workspace database: ${databasePath}`);
  if (secureCookie && !process.env.PUBLIC_ORIGIN) console.warn('Set PUBLIC_ORIGIN when deploying behind a TLS proxy.');
});

function close() { server.close(() => { db.close(); process.exit(0); }); }
process.on('SIGINT', close);
process.on('SIGTERM', close);
