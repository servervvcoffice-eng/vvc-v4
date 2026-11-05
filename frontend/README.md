# VVC Office frontend gateway

This folder is deployed as a separate Netlify site. It proxies every public route to the Render backend, so `/about`, `/admin`, `/login`, and other backend routes keep the frontend domain in the browser.

## Netlify environment variables

Set these in the Netlify site, not in GitHub:

```text
BACKEND_ORIGIN=https://your-render-service.example.com
VVC_GATEWAY_SECRET=<the same value configured on Render>
```

`VVC_GATEWAY_SECRET` is used only by the Netlify function. Never put it in `index.html`, browser JavaScript, or public environment variables.
