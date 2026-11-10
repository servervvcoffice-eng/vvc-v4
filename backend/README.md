# VVC Office

VVC Office is a private, single-project workspace implemented as a Rust/Axum service. The public login page is available at `/login`; `/home`, `/about`, `/admin`, and all private assets are served only after server-side authentication and explicit permission checks. `project/` is a private page workspace, not a public static web root. Built-in pages keep their explicit handlers, while new page folders are discovered automatically at runtime.

Unknown paths such as `/unknown` and `/unknown/hello` return the supplied frosted-glass 404 page with a Home link. An authenticated account without `admin.dashboard.read` also receives that same 404 page for `/admin`, avoiding disclosure of the Admin route.

The Admin Panel Spam tab records non-health request attempts with username or anonymous status, IP, a deterministic SHA-256 device fingerprint derived from client hints, device model, user-agent/device string, route or file path, HTTP method, status code, and timestamp. It supports Today, 7 Days, 30 Days, and All filters. Clearing Spam logs is a separate permissioned, CSRF-protected operational action; the durable schema is represented by `spam_logs` in the migration.

## Run locally

Install Rust 1.78+ and run:

```bash
cp .env.example .env
# Set VVC_DEV_PASSWORD to a local-only value.
COOKIE_SECURE=false cargo run --manifest-path Cargo.toml
```

Open `http://localhost:3000/login`. The development seed account is `superadmin`; its password is the value of `VVC_DEV_PASSWORD`. This process-local repository is intentional for a credential-free Preview and test run. It is not the durable production store.

### Admin page assets

The Admin Panel is self-contained: its reference-matched CSS and JavaScript are embedded in `project/admin/index.html`, so the page still renders and functions if `style.css` or `app.js` is absent. Those files remain optional source-of-truth files for editing and can use any filename. Additional files placed under `project/admin/` can be connected from the page and are served only to authenticated users with `admin.dashboard.read` through `/assets/admin/<safe-relative-path>`; traversal, control characters, and absolute paths are rejected.

### Add a page by uploading files only

Create a folder under `project/` with an `index.html` file; no Rust route, handler, permission catalog, or route-manifest edit is required:

```text
project/reports/
├── index.html
├── style.css
├── helpers.js
└── app.js
```

The page is automatically available to authenticated users at `/reports`. Connect same-folder CSS or JavaScript using the page slug:

```html
<link rel="stylesheet" href="/assets/reports/style.css">
<script src="/assets/reports/helpers.js" defer></script>
<script src="/assets/reports/app.js" defer></script>
```

Any safe nested `.html`, `.css`, or `.js` file under that folder is served through `/assets/reports/...`; assets require an authenticated session. New pages are authenticated by default and available to all authenticated roles. Keep secrets, server code, migrations, and database credentials outside `project/`. Path traversal, absolute paths, control characters, symlinks escaping the page folder, and unsupported file types are rejected. The route manifest discovers the new page automatically.

## Production persistence and deployment

Apply `migrations/001_init.sql` to a dedicated Supabase PostgreSQL project. Configure `DATABASE_URL` with a least-privilege application credential, keep the Supabase service-role credential only on the trusted backend, and never expose it to browser code. The production repository adapter should persist users, role assignments, sessions, operational logs, and audit/security events in PostgreSQL. Use Redis (`REDIS_URL`) for distributed login throttling and short-lived abuse state; Redis must not be the only durable audit or account store.

`config/render.yaml` uses Render's native Rust runtime with `cargo build --release` and the compiled binary start command. `REDIS_URL` is used for distributed login throttling: the service pings Redis during startup, `/readyz` reports unavailable while Redis cannot be pinged, and production startup fails if Redis is absent or unreachable. Preview may omit `REDIS_URL` and then uses a process-local fallback. The Redis key contains only a SHA-256 digest of the client IP and expires after the one-minute login window. The PostgreSQL adapter remains partial: user loading/synchronization is implemented, but sessions and operational/audit records are still process-local, and the one-time bootstrap flow is not wired into startup. Treat production as blocked on those durable PostgreSQL gaps even though Redis itself is now wired. Put the eventual Render origin behind the Cloudflare Worker in `cloudflare/worker/index.js`, set a rotated `VVC_GATEWAY_SECRET` in both server-side secret stores, and configure Cloudflare WAF/rate rules. The backend still performs authentication and authorization even when a request passed the gateway. If the Render origin cannot be made private, require gateway verification on every relevant request and restrict origin access at the hosting layer where possible.

### Cloudflare Worker deployment

The Worker gateway configuration is in `cloudflare/worker/wrangler.toml`. Set `ORIGIN_URL` to the Render service URL without a trailing path, and keep `ORIGIN_GATEWAY_SECRET` only as a Worker secret. Use the same randomly generated value for Render's `VVC_GATEWAY_SECRET`; never commit either value:

```bash
cd cloudflare/worker
npx wrangler login
npx wrangler secret put ORIGIN_GATEWAY_SECRET
npx wrangler deploy
```

The Worker strips client-supplied identity and forwarding headers, overwrites the gateway header, and forwards the request to Render. Configure the public DNS route to the Worker, then add Cloudflare WAF and rate-limit rules. Do not expose the Render hostname publicly if the hosting plan supports private origin controls. If the origin remains reachable, the Rust backend's gateway check must stay enabled with `VVC_GATEWAY_SECRET` set; otherwise direct-origin requests are not protected by the edge layer.

## Security posture

Argon2id hashes passwords. Session identifiers are random opaque values stored server-side and rotated on login and privilege changes. Cookies are Secure and HttpOnly with `SameSite=None` for embedded HTTPS Preview; state-changing requests require the per-session CSRF token in `X-CSRF-Token`. The service uses a strict content-security policy, request body limits, timeouts, generic login failures, rate limits, audit/activity separation, and protected last-Super-Admin safeguards.

The admin clear actions remove only selected operational Views, Activity, or Failed Login entries. They never remove accounts, roles, permissions, sessions, workspace configuration, or security audit records. IP and device fields are included for abuse detection and operational review; define a retention period appropriate to your privacy obligations before production use.

No system can honestly guarantee 100% security. Rust does not prevent authorization, dependency, deployment, configuration, or operational vulnerabilities, and an authorized browser user can inspect content delivered to their browser. Treat OWASP ASVS Level 2, the OWASP API Security Top 10, NIST Zero Trust principles, least privilege, defense in depth, dependency auditing, backups, and tested recovery as ongoing engineering work.

## Verification

```bash
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
```

The smoke script in `tests/smoke.sh` checks public login, redirect protection, private assets, login, CSRF enforcement, and the health endpoint against a running local server. Do not point destructive tests at production data; the managed platform database can be shared by development and production.
