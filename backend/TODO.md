# AegisCore delivery checklist

## Current state

The route boundary, protected pages/assets, session authentication, CSRF, RBAC, Admin Panel UI/API, operational-log safeguards, migration, Cloudflare example, deployment files, strict Rust checks, and smoke suite are implemented and verified in Preview. The PostgreSQL/Redis persistence adapter and one-time production bootstrap flow remain open by design; the binary now refuses `APP_ENV=production` rather than silently running the ephemeral repository.

## 1. Private workspace and route boundary
- [ ] Keep every project file inside the single top-level `backend/` folder.
- [ ] Make `GET /login` public; require authentication plus explicit permissions for `/home` and `/about`; require explicit administrative permission for `/admin`.
- [ ] Never expose `backend/project/` as a public static directory; serve private files only through authenticated, authorized Rust routes with a strict allowlist, no directory listing, no path traversal, and no arbitrary file reads.
- [ ] Return a safe 403 or non-looping allowed redirect for authenticated users without permission; do not reveal whether a username exists on login failure.

## 2. Authentication, sessions, and request security
- [ ] Accept username/password, hash with Argon2id, never store plaintext passwords, and use opaque cryptographically random server-side session IDs.
- [ ] Use Secure, HttpOnly, appropriate SameSite cookies; rotate sessions after login and privilege changes; enforce idle and absolute expiry; revoke on logout, disablement, and security-sensitive events.
- [ ] Protect state changes with CSRF validation, rate-limit login attempts, apply progressive abuse controls, validate inputs, use bounded requests, safe response headers, strict CORS, and parameterized database-query boundaries.

## 3. Roles and permissions
- [ ] Implement Super Admin, delegated Admin, and optional User semantics with granular permissions.
- [ ] Prevent ordinary Admins from creating/assigning Super Admin privileges or granting permissions beyond delegation scope.
- [ ] Check exact permissions on every protected page and every protected API operation; frontend visibility is not authorization.

## 4. Admin panel and APIs
- [ ] Implement responsive AegisCore-branded Dashboard, Users, Views, Activity, and Failed Logins panels with accessible loading, empty, and error states, search, filters, mobile navigation, profile, and sign-out.
- [ ] Implement authenticated, permission-checked API endpoints for stats, activity, users, roles, views, failed logins, role updates, block/unblock, user deletion, and selected-period operational-log clearing.
- [ ] Dashboard must show Total Users, Today Views, 7-Day Views, Blocked Users, recent activity, Today/7 Days/30 Days/All filters, and clear only Views/Activity/Failed Login operational logs.
- [ ] User management must validate username/email/password/role, never return password hashes or sensitive auth data, enforce delegated role changes, revoke sessions on block/delete, and protect the last active Super Admin.
- [ ] Views must track only implemented Home/About/Admin pages, use pagination and bounded limits, document privacy/retention for IP/device data, and support page/date filtering and operational clearing.
- [ ] Activity and failed-login panels must provide required fields and filters while protecting security audit and abuse records from ordinary clearing.

## 5. Data, audit, and edge architecture
- [ ] Include Supabase PostgreSQL migrations for users, roles, permissions, user_roles, role_permissions, sessions, login_attempts, audit_logs, security_events, workspace_settings, views, and activity logs.
- [ ] Include Redis rate-limit/cache guidance; do not use Redis as the durable audit/account store.
- [ ] Include Cloudflare Worker/WAF guidance for stripping untrusted identity headers, origin verification, and forwarding to Render; keep application auth mandatory.
- [ ] Record security-relevant events without passwords, session cookies, secrets, or hashes; document retention, backups, recovery, TLS, CSP, CORS, dependency auditing, and remaining risks.

## 6. Verification and delivery
- [ ] Include automated Rust tests for authentication, authorization, CSRF, session expiry, path traversal, direct private-file access, admin permissions, destructive actions, and audit protections.
- [ ] Run formatting, compilation, tests, dependency/security checks, and a security-focused review before declaring completion.
- [ ] Provide concise deployment requirements, manual secret/configuration steps, and an honest statement that no system is 100% secure.
