/**
 * AegisCore edge gateway example.
 * Bind ORIGIN_URL and ORIGIN_GATEWAY_SECRET as Worker-side secrets/vars.
 * Configure Cloudflare WAF and rate rules before this Worker.
 */
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/healthz') return new Response('ok', { status: 200 });
    const forwarded = new Request(env.ORIGIN_URL + url.pathname + url.search, request);
    const headers = new Headers(request.headers);
    // Never trust client-supplied identity/forwarding headers.
    for (const name of ['x-aegis-gateway', 'x-user-id', 'x-user-role', 'x-forwarded-user', 'x-forwarded-for']) headers.delete(name);
    headers.set('x-aegis-gateway', env.ORIGIN_GATEWAY_SECRET);
    headers.set('x-forwarded-proto', 'https');
    headers.set('x-aegis-request-id', crypto.randomUUID());
    return fetch(new Request(forwarded, { headers }));
  }
};
