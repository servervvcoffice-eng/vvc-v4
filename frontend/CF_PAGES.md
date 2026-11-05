# Cloudflare Pages deployment

This frontend can be deployed as a Cloudflare Pages project named `vvc-office`. The catch-all Pages Function in `functions/[[path]].js` proxies every route and protected asset to the Render backend.

## Pages project settings

- Repository: `servervvcoffice-eng/vvc-v4`
- Root directory: `frontend`
- Framework preset: None
- Build command: leave blank
- Build output directory: `.`
- Project name: `vvc-office`

Cloudflare Pages should detect `functions/[[path]].js` automatically.

## Pages environment variables

Add these as server-side variables/secrets for Production and Preview:

```text
BACKEND_ORIGIN=https://your-render-service.example.com
VVC_GATEWAY_SECRET=<the same secret configured as Render VVC_GATEWAY_SECRET>
```

Set `VVC_GATEWAY_SECRET` as an encrypted Secret, not a public variable. Do not place it in `index.html`, browser JavaScript, or GitHub.

After deployment, test:

```text
https://vvc-office.pages.dev/login
https://vvc-office.pages.dev/about
https://vvc-office.pages.dev/assets/login.css
```

Unauthenticated `/about` should redirect to `/login`; the login page and its assets should return `200`.
