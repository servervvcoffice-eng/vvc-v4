const HOP_BY_HOP = new Set([
  'connection',
  'content-length',
  'content-encoding',
  'host',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
]);

export async function onRequest(context) {
  const { request, env } = context;
  const gatewaySecret = env.VVC_GATEWAY_SECRET;
  const backendOrigin = env.BACKEND_ORIGIN;

  if (!gatewaySecret || !backendOrigin) {
    return new Response('Cloudflare Pages proxy is not configured', { status: 503 });
  }

  let backend;
  try {
    backend = new URL(backendOrigin);
    if (backend.protocol !== 'https:') throw new Error('backend must use HTTPS');
  } catch (_error) {
    return new Response('Cloudflare Pages proxy is not configured', { status: 503 });
  }

  const incoming = new URL(request.url);
  backend.pathname = `${backend.pathname.replace(/\/$/, '')}${incoming.pathname}`;
  backend.search = incoming.search;

  const headers = new Headers(request.headers);
  for (const name of [
    ...HOP_BY_HOP,
    'x-vvc-gateway',
    'x-user-id',
    'x-user-role',
    'x-forwarded-for',
    'x-forwarded-host',
    'x-forwarded-proto',
    'x-vvc-request-id',
  ]) {
    headers.delete(name);
  }
  headers.set('x-vvc-gateway', gatewaySecret);
  headers.set('x-forwarded-proto', 'https');
  headers.set('x-forwarded-host', incoming.host);
  headers.set('x-vvc-request-id', crypto.randomUUID());

  let response;
  try {
    response = await fetch(new Request(backend, {
      method: request.method,
      headers,
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'manual',
    }));
  } catch (_error) {
    return new Response('Backend unavailable', { status: 502 });
  }

  const responseHeaders = new Headers(response.headers);
  for (const name of HOP_BY_HOP) responseHeaders.delete(name);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}
