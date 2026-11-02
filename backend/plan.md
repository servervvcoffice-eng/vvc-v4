# AegisCore implementation plan

## Scope and implementation approach

AegisCore is implemented as one private workspace. The Rust/Axum service is the only web root: it serves the public login page directly and serves every private HTML/CSS/JavaScript asset through explicit authenticated routes. `backend/project/` is never mounted as a static directory and no request-controlled filesystem path is read.

The first runnable slice uses a process-local repository so Preview and automated tests work without external credentials. The production boundary is documented and migration-ready: PostgreSQL/Supabase owns durable users, roles, sessions, operational logs, and audit records; Redis owns distributed rate-limit counters and short-lived abuse state. The migration schema, environment contract, Cloudflare Worker, Dockerfile, and Render configuration are included under `backend/`.

Authentication uses Argon2id password hashes, opaque random session IDs, server-side session state, rotation on login and privilege changes, idle/absolute expiry, CSRF tokens for state changes, secure HttpOnly cookies, generic login failures, request limits, and per-IP throttling. Authorization is deny-by-default and checked independently on every protected page and API operation. Super Admin authority is distinct from delegated Admin permissions, and destructive operations protect the last active Super Admin.

The admin UI is a responsive iOS-inspired frosted-glass console. It uses a dark navy canvas, a mint signature accent, compact data cards, a mobile overlay sidebar, accessible controls, bounded tables, clear empty/loading/error states, and confirmation prompts for destructive actions. The UI never substitutes hidden buttons for server authorization.

## Project structure

- `backend/src/`: Axum application, security primitives, in-memory development repository, route handlers, and tests.
- `backend/public/login/`: the only unauthenticated page and its assets.
- `backend/project/home/`, `about/`, `admin/`: private page sources compiled into authenticated allowlisted routes.
- `backend/migrations/`: Supabase PostgreSQL schema with RLS-oriented boundaries and operational/audit log separation.
- `backend/cloudflare/worker/`: edge gateway/WAF forwarding example that strips untrusted identity headers and adds a signed origin header.
- `backend/config/`: Render and deployment configuration examples.
- `backend/tests/`: smoke/security test helpers.
- `backend/.env.example`, `README.md`, and this plan: deployment and operational documentation.

## Design direction

Three candidate styles were considered: **Quiet security console** (0.07), **Editorial operations desk** (0.05), and **Carbon glass command center** (0.08). The chosen direction is **Quiet security console**.

- **Design Movement:** iOS utility surfaces translated into a restrained security operations console.
- **Core Principles:** calm hierarchy, high information density without visual noise, immediate feedback, and visible trust boundaries.
- **Color Philosophy:** deep blue-black surfaces signal focus and privacy; mint marks healthy/allowed states; amber and coral are reserved for warnings and destructive actions.
- **Layout Paradigm:** a persistent glass rail anchors navigation while the workspace flows as a wide operational canvas; tables and panels align to the rail rather than a centered marketing grid.
- **Signature Elements:** a mint “A” shield mark, translucent sidebar glass, and thin status rails on metric cards.
- **Interaction Philosophy:** actions are explicit, reversible where possible, and explain what will happen; errors stay near the action that caused them.
- **Animation:** subtle 160–220ms fades and slide-ins only for navigation, panels, and status updates; no looping decoration; prefers-reduced-motion disables transitions.
- **Typography System:** system UI stack for compact controls and data, with a heavier geometric display weight for headings; hierarchy comes from size, weight, and tracking rather than many colors.
- **Brand Essence:** private operational control for teams who need clarity over spectacle; precise, calm, accountable.
- **Brand Voice:** short, direct, operational. Example lines: “Access is explicit.” and “Operational logs can be cleared; security history cannot.”
- **Wordmark & Logo:** the AegisCore wordmark is paired with a shield-shaped A monogram constructed from two opposing chevrons.
- **Signature Brand Color:** Aegis Mint `#7EF2C2`.
