/**
 * VVC Office edge gateway.
 * ORIGIN_URL is a Worker variable; ORIGIN_GATEWAY_SECRET is a Worker secret.
 * Configure Cloudflare WAF and rate rules before this Worker.
 */
export default {
  async fetch(request, env) {
    if (!env.ORIGIN_URL || !env.ORIGIN_GATEWAY_SECRET) {
      return new Response('Gateway is not configured', { status: 503 });
    }
    const url = new URL(request.url);
    const origin = new URL(env.ORIGIN_URL);
    origin.pathname = `${origin.pathname.replace(/\/$/, '')}${url.pathname}`;
    origin.search = url.search;
    const forwarded = new Request(origin, request);
    const headers = new Headers(request.headers);
    // Never trust client-supplied identity/forwarding headers.
    for (const name of [
      'x-aegis-gateway',
      'x-user-id',
      'x-user-role',
      'x-forwarded-user',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-forwarded-proto',
      'x-aegis-request-id',
    ]) headers.delete(name);
    headers.set('x-aegis-gateway', env.ORIGIN_GATEWAY_SECRET);
    headers.set('x-forwarded-proto', 'https');
    headers.set('x-forwarded-host', url.host);
    headers.set('x-aegis-request-id', crypto.randomUUID());
    return fetch(new Request(forwarded, { headers }));
  }
};
