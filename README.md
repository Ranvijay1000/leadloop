# Leadloop

Leadloop is an original, responsive CRM prototype with a usable local account and workspace backend. It has two modes:

- **Demo workspace:** no sign-in; sample records and edits are saved in this browser's local storage.
- **Account workspace:** create an account with a 12+ character password; records are stored in the local SQLite database and scoped to the authenticated workspace membership.

Neither mode connects to external email, messaging, calling, calendar, AI, payment, or ads providers. The interface identifies those integrations as disconnected or demo-only; it does not claim to send messages or confirm provider transactions.

## Run locally

Requires Node.js 22.5 or later. The backend uses Node's built-in SQLite module and the standard library; there are no packages to install. SQLite is currently an experimental Node API, so use the documented Node 22 runtime or newer.

```sh
npm start
```

Open [http://127.0.0.1:4173](http://127.0.0.1:4173). The first successful sign-up creates a workspace and owner membership. Existing accounts can sign in. The server creates `data/leadloop.sqlite` automatically; database files are ignored by Git. Set `PORT` to change the port and `LEADLOOP_DB` to choose a different database file path. `HOST` defaults to `127.0.0.1`.

Check JavaScript syntax with `npm run check`.

## Authentication and data boundary

- Sign-up validates email, requires a 12–128 character password, hashes passwords with scrypt and a per-user salt, and creates the user, workspace, owner membership, and empty workspace state in a transaction.
- Sign-in uses a generic failure response and constant-time hash comparison. Authentication is an opaque random, expiring session token stored hashed in SQLite and carried in an `HttpOnly`, `SameSite=Lax` cookie.
- State reads and writes derive `workspace_id` from the validated session and active membership. The API never accepts a workspace ID from the browser for these routes. SQL foreign keys, membership indexes, JSON/body size checks, mutation rate limits, and same-origin checks are enabled.
- Owners and admins can update member roles and create pending invitations. The server prevents changing the owner role and does not accept `owner` as an assignable role. Managers can edit shared CRM state; agents can read it, while state writes are denied server-side.
- Workspace profile edits are server-validated and limited to owners/admins. Administrative and financial actions are recorded in an append-only SQLite audit table; owners/admins can read the latest 100 events.
- When a payment record is first marked paid in an authenticated workspace, the server records an audit event in the same transaction. Confirmed payment records cannot be silently edited or removed through the workspace-state API.
- The account workspace's CRM state is stored as one workspace-scoped JSON document. This is a compact persistence layer for the prototype, not a normalized production schema. All application arrays are validated and size-limited; provider keys and passwords are never part of that document.
- The Team page lists active memberships and pending invitations from the server database. Invitation creation is persisted but email delivery and acceptance links are not implemented yet.

Use the local app only with development data. For a public production deployment, move to a managed identity system and a normalized Postgres schema with database row policies, password reset and email verification, invitation token lifecycle, audit records, backups, monitoring, strict rate limiting across instances, CSRF token strategy compatible with the chosen proxy, HTTPS, secure cookie and trusted-host configuration, and security review. The current SQLite JSON document model is a functional local foundation, not a certification of production readiness.

## Implemented workspace

- Public home, features, and example pricing pages; real local account sign-up and sign-in; explicit demo mode.
- Workspace routes for overview, leads, pipeline, inbox, calls, calendar, workflows, campaigns, payments, reports, team, and settings.
- Lead creation/editing, CSV import with duplicate skipping, email duplicate warning, search/filter/CSV export, capture-form preview, tasks, draggable deal stages, conversation drafts, local notes, manual call/meeting/payment records, workflow controls, team roles, pending invitations, and activity history.
- Account-workspace records save to and reload from SQLite. The server enforces workspace scoping for account state, member reads, invitation writes, and role updates.
- Demo records continue to use local storage and are not copied into newly created account workspaces.

## API routes

- `GET /api/health`, `GET /api/session`
- `POST /api/auth/signup`, `POST /api/auth/login`, `POST /api/auth/logout`
- `GET /api/state`, `PUT /api/state`
- `PATCH /api/workspace`
- `GET /api/members`, `PATCH /api/members/:userId`, `POST /api/invitations`
- `GET /api/audit` (owner/admin)

All state and membership endpoints use the session's workspace membership. Mutations must include a same-origin browser `Origin` header. `PUT /api/state` accepts only known top-level collections and has a 2 MiB limit. Password reset is deliberately unavailable until an email provider is configured.

## Configuration and integrations

`.env.example` contains placeholder names only. The current app reads `PORT`, `HOST`, `LEADLOOP_DB`, `NODE_ENV`, and (behind a TLS proxy) `PUBLIC_ORIGIN` from the server environment. Keep provider credentials on the server; do not add secrets to `app.js`, static files, or the workspace-state payload.

The Settings integration cards are setup boundaries. Build separate server adapters for form/webhook intake, email and WhatsApp, an AI provider grounded in approved workspace knowledge, calling, Google Calendar, Razorpay/Stripe payment links and signed webhooks, and Meta/Google Ads. Add signature verification, idempotent event storage, retries where safe, consent/channel checks, and audit records before enabling live actions. Payments must only be confirmed from trusted provider webhooks or authorized audited manual updates.

## Deployment

The included server is a local prototype server and binds to loopback. It is not a production hosting server. A production frontend/backend needs HTTPS, trusted reverse-proxy configuration, `NODE_ENV=production`, the correct `PUBLIC_ORIGIN`, secure cookie delivery, durable backed-up storage, and hardened auth/session operations. The current local sign-up does not include email verification or password-reset delivery.
