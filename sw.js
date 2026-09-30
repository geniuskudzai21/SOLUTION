/* ------------------------------------------------------------------ *
 * Cyber Shield Zimbabwe - offline app shell
 *
 * Precache strategy: stale-while-revalidate. The cached copy answers
 * immediately, so the app opens with no network, and a fresh copy is
 * fetched in the background so an edit shows up on the next reload.
 *
 * Bump CACHE when shipping a new build.
 * ------------------------------------------------------------------ */

const CACHE = 'cyber-shield-v1';

const SHELL = [
  './',
  './index.html',
  './slides.html',
  './manifest.webmanifest',
  './css/styles.css',
  './js/engine.js',
  './js/dataset.js',
  './js/app.js',
  './assets/icon-192.png',
  './assets/icon-512.png',
  './assets/icon-maskable.png',
  './assets/apple-touch-icon.png',
];

self.addEventListener('install', (e) => {
  e.waitUntil(
    caches
      .open(CACHE)
      // One bad path must not abort the whole install.
      .then((c) => Promise.all(SHELL.map((p) => c.add(p).catch(() => null))))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;

  if (req.method !== 'GET') return;

  // Never touch the font CDN or anything else cross-origin.
  if (new URL(req.url).origin !== self.location.origin) return;

  e.respondWith(
    caches.open(CACHE).then(async (c) => {
      const cached = await c.match(req);

      const network = fetch(req)
        .then((res) => {
          if (res && res.ok && res.type === 'basic') c.put(req, res.clone());
          return res;
        })
        .catch(() => null);

      if (cached) return cached;

      const fresh = await network;
      if (fresh) return fresh;

      // Offline and unseen: send the app shell so the user lands somewhere useful.
      if (req.mode === 'navigate') return c.match('./index.html');
      return new Response('', { status: 504, statusText: 'Offline' });
    })
  );
});
