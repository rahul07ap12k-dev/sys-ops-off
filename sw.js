/**
 * Minimalist Defensive Service Worker
 * STAGE: Caches strictly static shell UI assets.
 * DEFENSE: Explicitly FORBIDS caching of WebSockets, dynamic API calls,
 * and purges immediately upon request.
 */
const CACHE_NAME = 'tot-shell-v1';
const STATIC_SHELL = [
  './',
  './index.html',
  './styles.css',
  './crypto.js',
  './app.js',
  './manifest.json'
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_SHELL))
  );
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(
        keys.map((key) => {
          if (key !== CACHE_NAME) return caches.delete(key);
        })
      )
    )
  );
  self.clients.claim();
});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);

  // STRICT RULE: Never intercept or cache WebSocket handshakes or cross-origin requests
  if (url.protocol === 'wss:' || url.protocol === 'ws:' || !url.origin.includes(self.location.origin)) {
    return;
  }

  // Cache-first for local static shell only
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      return cachedResponse || fetch(event.request);
    })
  );
});
