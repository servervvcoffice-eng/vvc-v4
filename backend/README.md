# AegisCore

AegisCore is a private, single-project workspace implemented as a Rust/Axum service. The public login page is available at `/login`; `/home`, `/about`, `/admin`, and all private assets are served only after server-side authentication and explicit permission checks. `backend/project/` is source data compiled into allowlisted handlers; it is not a static web root.

## Run locally

Install Rust 1.78+ and run:

```bash
cp .env.example .env
# Set AEGIS_DEV_PASSWORD to a local-only value.
COOKIE_SECURE=false cargo run --manifest-path Cargo.toml
```

Open `http://localhost:3000/login`. The development seed account is `superadmin`; its password is the value of `AEGIS_DEV_PASSWORD`. This process-local repository is intentional for a credential-free Preview and test run. It is not the durable production store.

### Admin page assets

The Admin Panel is self-contained: its reference-matched CSS and JavaScript are embedded in `project/admin/index.html`, so the page still renders and functions if `style.css` or `app.js` is absent. Those files remain optional source-of-truth files for editing and can use any filename. Additional files placed under `project/admin/` can be connected from the page and are served only to authenticated users with `admin.dashboard.read` through `/assets/admin/<safe-relative-path>`; traversal, control characters, and absolute paths are rejected.

## Production persistence and deployment

Apply `migrations/001_init.sql` to a dedicated Supabase PostgreSQL project. Configure `DATABASE_URL` with a least-privilege application credential, keep the Supabase service-role credential only on the trusted backend, and never expose it to browser code. The production repository adapter should persist users, role assignments, sessions, operational logs, and audit/security events in PostgreSQL. Use Redis (`REDIS_URL`) for distributed login throttling and short-lived abuse state; Redis must not be the only durable audit or account store.

`Dockerfile` builds the service and honors `PORT`; its default `APP_ENV=preview` is intentionally for a temporary hosted Preview and uses server-process state. `config/render.yaml` describes the intended Render production shape, but the current binary deliberately refuses `APP_ENV=production` because its runnable repository is still process-local. Do not deploy it as production until the PostgreSQL/Supabase and Redis adapters, one-time bootstrap flow, and gateway secret enforcement are wired. Put the eventual Render origin behind the Cloudflare Worker in `cloudflare/worker/index.js`, set a rotated `AEGIS_GATEWAY_SECRET` in both server-side secret stores, and configure Cloudflare WAF/rate rules. The backend still performs authentication and authorization even when a request passed the gateway. If the Render origin cannot be made private, require gateway verification on every relevant request and restrict origin access at the hosting layer where possible.

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
