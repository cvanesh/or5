// Password gate. Derives an AES-GCM key with PBKDF2 from the user's
// passphrase, decrypts data.bin, hands the manifest + key to the
// service worker, and navigates into the (intercepted) app.

(() => {
  const PBKDF2_ITERS = 600000;
  const SALT_LEN = 16;
  const APP_PATH = 'app/index.html';

  const $ = id => document.getElementById(id);
  const setStatus = (msg, isErr) => {
    const el = $('status');
    el.textContent = msg || '';
    el.classList.toggle('err', !!isErr);
  };

  async function deriveKey(pwd, salt) {
    const baseKey = await crypto.subtle.importKey(
      'raw', new TextEncoder().encode(pwd), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['decrypt']
    );
  }

  async function unlock(pwd) {
    if (!('serviceWorker' in navigator)) throw new Error('Browser unsupported');

    setStatus('Loading…');
    const buf = new Uint8Array(
      await (await fetch('data.bin', { cache: 'no-store' })).arrayBuffer()
    );
    const salt = buf.slice(0, SALT_LEN);
    const iv = buf.slice(SALT_LEN, SALT_LEN + 12);
    const ct = buf.slice(SALT_LEN + 12);

    setStatus('Verifying…');
    const key = await deriveKey(pwd, salt);

    let plain;
    try {
      plain = new Uint8Array(
        await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct)
      );
    } catch {
      throw new Error('Wrong password');
    }
    const manifest = JSON.parse(new TextDecoder().decode(plain));
    const keyRaw = await crypto.subtle.exportKey('raw', key);

    setStatus('Initializing…');
    const reg = await navigator.serviceWorker.register('sw.js', { scope: './' });
    if (reg.installing) await waitState(reg.installing, 'activated');
    else if (reg.waiting)   await waitState(reg.waiting, 'activated');
    if (!navigator.serviceWorker.controller) {
      await new Promise(r => navigator.serviceWorker.addEventListener('controllerchange', r, { once: true }));
    }

    const ack = new Promise((resolve, reject) => {
      const ch = new MessageChannel();
      ch.port1.onmessage = e => {
        if (e.data?.type === 'ready') resolve();
        else reject(new Error('SW init failed'));
      };
      navigator.serviceWorker.controller.postMessage(
        { type: 'init', manifest, keyRaw },
        [ch.port2]
      );
    });
    await ack;

    setStatus('Opening…');
    location.replace(APP_PATH);
  }

  function waitState(sw, state) {
    if (sw.state === state) return Promise.resolve();
    return new Promise(r => sw.addEventListener('statechange', () => sw.state === state && r()));
  }

  $('f').addEventListener('submit', async e => {
    e.preventDefault();
    $('go').disabled = true;
    try {
      await unlock($('pw').value);
    } catch (err) {
      setStatus(err.message || 'Failed', true);
      $('go').disabled = false;
      $('pw').select();
    }
  });

  // Auto-resume: if SW already has a manifest cached from a previous session,
  // skip the password prompt entirely.
  (async () => {
    if (!('serviceWorker' in navigator)) return;
    const reg = await navigator.serviceWorker.getRegistration('./');
    if (!reg || !reg.active) return;
    const ok = await new Promise(resolve => {
      const ch = new MessageChannel();
      ch.port1.onmessage = e => resolve(e.data?.type === 'has-manifest');
      reg.active.postMessage({ type: 'ping' }, [ch.port2]);
      setTimeout(() => resolve(false), 500);
    });
    if (ok) location.replace(APP_PATH);
  })();
})();
