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

exports.handler = async (event) => {
  const gatewaySecret = process.env.AEGIS_GATEWAY_SECRET;
  const backendOrigin = process.env.BACKEND_ORIGIN;
  if (!gatewaySecret || !backendOrigin) {
    return { statusCode: 503, body: 'Frontend proxy is not configured' };
  }
  let backend;
  try {
    backend = new URL(backendOrigin);
    if (backend.protocol !== 'https:') throw new Error('backend must use HTTPS');
  } catch (_error) {
    return { statusCode: 503, body: 'Frontend proxy is not configured' };
  }

  let incoming;
  try {
    incoming = event.rawUrl ? new URL(event.rawUrl) : null;
  } catch (_error) {
    incoming = null;
  }
  const path = incoming?.pathname || event.path.replace(/^\/.netlify\/functions\/proxy/, '') || '/';
  const query = incoming?.search || (event.rawQuery ? `?${event.rawQuery}` : '');
  const target = `${backend.origin}${backend.pathname.replace(/\/$/, '')}${path}${query}`;
  const headers = new Headers();

  for (const [name, value] of Object.entries(event.headers || {})) {
    const lower = name.toLowerCase();
    if (!HOP_BY_HOP.has(lower) && ![
      'x-aegis-gateway',
      'x-user-id',
      'x-user-role',
      'x-forwarded-for',
      'x-forwarded-host',
      'x-forwarded-proto',
    ].includes(lower)) {
      headers.set(name, value);
    }
  }
  headers.set('x-aegis-gateway', gatewaySecret);
  headers.set('x-forwarded-proto', 'https');
  headers.set('x-forwarded-host', event.headers?.host || '');

  let body;
  if (!['GET', 'HEAD'].includes(event.httpMethod)) {
    body = event.isBase64Encoded
      ? Buffer.from(event.body || '', 'base64')
      : event.body || undefined;
  }

  let response;
  try {
    response = await fetch(target, {
      method: event.httpMethod,
      headers,
      body,
      redirect: 'manual',
    });
  } catch (_error) {
    return { statusCode: 502, body: 'Backend unavailable' };
  }

  const responseHeaders = {};
  for (const [name, value] of response.headers.entries()) {
    if (!HOP_BY_HOP.has(name)) responseHeaders[name] = value;
  }

  const responseBody = Buffer.from(await response.arrayBuffer()).toString('base64');
  return {
    statusCode: response.status,
    headers: responseHeaders,
    body: responseBody,
    isBase64Encoded: true,
  };
};
