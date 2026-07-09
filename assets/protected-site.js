(function () {
  const PASS_KEY = 'protected-site-passphrase';
  const root = document.getElementById('protected-app');
  const form = document.getElementById('protected-form');
  const input = document.getElementById('protected-passphrase');
  const message = document.getElementById('protected-message');

  function normalizeBasePath(input) {
    const raw = String(input || '').trim() || '/PCE-site/';
    const withLeading = raw.startsWith('/') ? raw : '/' + raw;
    return withLeading.endsWith('/') ? withLeading : withLeading + '/';
  }

  const basePath = normalizeBasePath(window.PROTECTED_SITE_BASE_PATH || '/PCE-site/');
  const isAssetView = new URLSearchParams(location.search).has('asset');

  function stripBasePath(pathname) {
    const clean = String(pathname || '/');
    if (clean === basePath) return '/';
    if (clean.startsWith(basePath)) return '/' + clean.slice(basePath.length).replace(/^\/+/, '');
    return clean.startsWith('/') ? clean : '/' + clean;
  }

  function toPublicPath(pathname) {
    return basePath + String(pathname || '').replace(/^\/+/, '');
  }

  function setMessage(text, error = true) {
    if (message) {
      message.textContent = text || '';
      message.style.color = error ? '#7a1f1f' : '#1f5d2a';
    }
  }

  function b64ToBytes(b64) {
    const clean = String(b64 || '').trim();
    const bin = atob(clean);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }

  function bytesToText(bytes) {
    return new TextDecoder().decode(bytes);
  }

  function escapeHtml(text) {
    return String(text)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function deriveKey(passphrase, salt, iterations) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      new TextEncoder().encode(passphrase),
      'PBKDF2',
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt,
        iterations: iterations || 120000,
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt']
    );
  }

  async function decryptEnvelope(envelope, passphrase) {
    const salt = b64ToBytes(envelope.salt);
    const iv = b64ToBytes(envelope.iv);
    const ciphertext = b64ToBytes(envelope.ciphertext);
    const key = await deriveKey(passphrase, salt, envelope.iterations);
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(plain);
  }

  async function fetchEnvelope(url) {
    const res = await fetch(url, { cache: 'no-store' });
    if (!res.ok) throw new Error('Conte�do indispon�vel.');
    return res.json();
  }

  function normalizedRoute(pathname) {
    if (!pathname || pathname === '/') return '/';
    return pathname.endsWith('/') ? pathname : pathname + '/';
  }

  function pagePayloadUrl() {
    const normalized = normalizedRoute(stripBasePath(currentRoute()));
    return toPublicPath('content' + normalized + 'index.html.enc');
  }

  function assetPayloadUrl(assetPath) {
    const clean = String(assetPath || '').split('?')[0].split('#')[0];
    const relative = stripBasePath(clean);
    return toPublicPath('content' + relative + '.enc');
  }

  function isLocalAssetPath(pathname) {
    return /.(pdf|png|jpe?g|gif|webp|bmp|svg|tiff?|txt|csv|json|md)$/i.test(String(pathname || ''));
  }

  function prepareLocalAssetPlaceholders(rootEl, pageUrl) {
    rootEl.querySelectorAll('img[src], source[src], iframe[src], audio[src], video[src], embed[src], object[data]').forEach((el) => {
      const attr = el.tagName.toLowerCase() === 'object' ? 'data' : 'src';
      const raw = el.getAttribute(attr);
      if (!raw || raw.startsWith('data:') || raw.startsWith('blob:')) return;
      const resolved = new URL(raw, pageUrl).pathname;
      if (!isLocalAssetPath(resolved)) return;
      el.setAttribute('data-protected-' + attr, raw);
      el.removeAttribute(attr);
    });
  }

  async function hydrateLocalAssets(rootEl, pageUrl) {
    const nodes = rootEl.querySelectorAll('[data-protected-src], [data-protected-data]');
    for (const el of nodes) {
      const attr = el.hasAttribute('data-protected-data') ? 'data' : 'src';
      const raw = el.getAttribute('data-protected-' + attr);
      if (!raw) continue;
      const resolvedUrl = new URL(raw, pageUrl);
      const assetPath = resolvedUrl.pathname;
      try {
        const envelope = await fetchEnvelope(assetPayloadUrl(assetPath));
        const bytes = await decryptEnvelope(envelope, currentPassphrase());
        const blob = new Blob([bytes], { type: envelope.mime || 'application/octet-stream' });
        const objectUrl = URL.createObjectURL(blob);
        el.setAttribute(attr, objectUrl);
        el.removeAttribute('data-protected-' + attr);
      } catch (err) {
        console.warn('Failed to load protected asset:', assetPath, err);
      }
    }
  }

  async function injectPage(html, title, description) {
    if (title) document.title = title;
    if (description) {
      let meta = document.querySelector('meta[name="description"]');
      if (!meta) {
        meta = document.createElement('meta');
        meta.name = 'description';
        document.head.appendChild(meta);
      }
      meta.content = description;
    }
    const holder = document.createElement('div');
    holder.innerHTML = html;
    prepareLocalAssetPlaceholders(holder, location.href);
    document.body.className = '';
    document.body.innerHTML = holder.innerHTML;
    attachLinkInterception();
    await hydrateLocalAssets(document.body, location.href);
  }

  function renderAsset(bytes, mime, name) {
    const blob = new Blob([bytes], { type: mime || 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const main = root || document.querySelector('main');
    const filename = name || (new URL(location.href)).pathname.split('/').pop() || 'arquivo';
    const safeMime = mime || 'application/octet-stream';
    const textLike = safeMime.startsWith('text/') || safeMime.includes('json') || safeMime.includes('markdown') || safeMime.includes('csv');
    const text = textLike ? escapeHtml(bytesToText(bytes)) : '';
    if (main) {
      main.innerHTML = '<section class="protected-asset">' +
        '<p><strong>Arquivo:</strong> ' + escapeHtml(filename) + '</p>' +
        '<p><strong>Tipo:</strong> ' + escapeHtml(safeMime) + '</p>' +
        (safeMime.startsWith('image/') ? '<img alt="' + escapeHtml(filename) + '" src="' + url + '" />' : '') +
        (safeMime === 'application/pdf' ? '<iframe title="' + escapeHtml(filename) + '" src="' + url + '"></iframe>' : '') +
        (textLike ? '<pre>' + text + '</pre>' : '') +
        (!safeMime.startsWith('image/') && safeMime !== 'application/pdf' && !textLike ? '<p><a href="' + url + '" download="' + escapeHtml(filename) + '">Baixar arquivo</a></p>' : '') +
        '</section>';
    }
    if (!safeMime.startsWith('image/') && safeMime !== 'application/pdf' && !textLike) {
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.click();
    }
  }

  async function unlock(passphrase) {
    setMessage('Desbloqueando...', false);
    if (isAssetView) {
      const assetPath = new URLSearchParams(location.search).get('asset');
      const envelope = await fetchEnvelope(assetPayloadUrl(assetPath));
      const bytes = await decryptEnvelope(envelope, passphrase);
      sessionStorage.setItem(PASS_KEY, passphrase);
      renderAsset(bytes, envelope.mime, envelope.name);
      setMessage('');
      return;
    }

    const envelope = await fetchEnvelope(pagePayloadUrl());
    const bytes = await decryptEnvelope(envelope, passphrase);
    const payload = JSON.parse(bytesToText(bytes));
    sessionStorage.setItem(PASS_KEY, passphrase);
    await injectPage(payload.html || '', payload.title || document.title, payload.description || '');
    setMessage('');
  }

  function currentPassphrase() {
    return sessionStorage.getItem(PASS_KEY) || '';
  }

  function currentRoute() {
    return location.pathname;
  }

  function navigate(url) {
    const target = new URL(url, location.href);
    if (target.origin !== location.origin) return false;

    const assetLike = /\.(pdf|png|jpe?g|gif|webp|bmp|svg|tiff?|txt|csv|json|md)$/i.test(target.pathname);
    if (assetLike) {
      location.href = toPublicPath('?asset=' + encodeURIComponent(target.pathname));
      return true;
    }

    history.pushState({}, '', target.pathname + target.search + target.hash);
    void unlock(currentPassphrase()).catch((err) => setMessage(err.message || 'Falha ao carregar a p�gina.'));
    return true;
  }

  function attachLinkInterception() {
    document.querySelectorAll('a[href]').forEach((anchor) => {
      if (anchor.dataset.protectedBound) return;
      anchor.dataset.protectedBound = '1';
      anchor.addEventListener('click', (event) => {
        const href = anchor.getAttribute('href');
        if (!href || href.startsWith('#') || href.startsWith('mailto:') || href.startsWith('tel:')) return;
        if (anchor.target === '_blank' || anchor.hasAttribute('download')) return;
        const url = new URL(href, location.href);
        if (url.origin !== location.origin) return;
        event.preventDefault();
        navigate(url.href);
      });
    });
  }

  if (form && input) {
    form.addEventListener('submit', (event) => {
      event.preventDefault();
      unlock(input.value.trim()).catch((err) => setMessage(err.message || 'Senha inv�lida.'));
    });
  }

  window.addEventListener('popstate', () => {
    if (currentPassphrase()) {
      void unlock(currentPassphrase()).catch((err) => setMessage(err.message || 'Falha ao carregar a p�gina.'));
    }
  });

  const saved = currentPassphrase();
  if (saved) {
    if (input) input.value = saved;
    void unlock(saved).catch((err) => {
      sessionStorage.removeItem(PASS_KEY);
      setMessage(err.message || 'Senha inv�lida.');
    });
  }
})();
