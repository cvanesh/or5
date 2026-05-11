// Service worker that turns the encrypted bundle back into a normal site.
// All requests under <scope>/app/ are served from a decrypted manifest in
// memory; lazy assets (manual pages) are fetched as ciphertext, decrypted
// on demand, and cached. If the SW restarts and loses state, requests
// under /app/ redirect to the loader so the user re-enters the password.

const APP_PREFIX = 'app/';
const CIPHER_PREFIX = 'p/';
const IV_LEN = 12;

let manifest = null;     // { eager: { path: { mime, b64 } }, lazy: { path: { mime, id } } }
let cryptoKey = null;
const lazyCache = new Map(); // id -> Response

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));

self.addEventListener('message', async event => {
  const data = event.data || {};
  const reply = msg => event.ports[0]?.postMessage(msg);

  if (data.type === 'init') {
    manifest = data.manifest;
    cryptoKey = await crypto.subtle.importKey(
      'raw', data.keyRaw, 'AES-GCM', false, ['decrypt']
    );
    reply({ type: 'ready' });
  } else if (data.type === 'ping') {
    reply({ type: manifest ? 'has-manifest' : 'empty' });
  } else if (data.type === 'logout') {
    manifest = null;
    cryptoKey = null;
    lazyCache.clear();
    reply({ type: 'logged-out' });
  }
});

function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function makeResponse(bytes, mime) {
  return new Response(bytes, {
    headers: {
      'Content-Type': mime,
      'Cache-Control': 'no-store',
    },
  });
}

async function decryptBlob(buf) {
  const iv = buf.slice(0, IV_LEN);
  const ct = buf.slice(IV_LEN);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ct)
  );
}

self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  const scope = new URL(self.registration.scope);
  if (url.origin !== scope.origin) return;
  if (!url.pathname.startsWith(scope.pathname)) return;

  let rel = url.pathname.slice(scope.pathname.length);
  if (!rel.startsWith(APP_PREFIX)) return; // pass through (loader, data.bin, p/*.bin)

  rel = rel.slice(APP_PREFIX.length);
  if (rel === '' || rel.endsWith('/')) rel += 'index.html';

  event.respondWith(
    serve(rel, scope).catch(() =>
      new Response('Temporary error, please reload.', {
        status: 503,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' },
      })
    )
  );
});

async function serve(rel, scope) {
  if (!manifest || !cryptoKey) {
    return Response.redirect(new URL('index.html', scope).href, 302);
  }
  const eager = manifest.eager[rel];
  if (eager) return makeResponse(b64ToBytes(eager.b64), eager.mime);

  const lazy = manifest.lazy[rel];
  if (lazy) {
    const cached = lazyCache.get(lazy.id);
    if (cached) return cached.clone();
    let r, buf;
    try {
      r = await fetch(scope.pathname + CIPHER_PREFIX + lazy.id + '.bin', { cache: 'no-store' });
      if (!r.ok) return new Response('Not found', { status: 404 });
      buf = await r.arrayBuffer();
    } catch {
      return new Response('Network error, please reload.', { status: 503 });
    }
    const enc = new Uint8Array(buf);
    let bytes;
    try { bytes = await decryptBlob(enc); }
    catch { return new Response('Decrypt failed', { status: 500 }); }
    const resp = makeResponse(bytes, lazy.mime);
    lazyCache.set(lazy.id, resp.clone());
    return resp;
  }

  return new Response('Not found', { status: 404 });
}
