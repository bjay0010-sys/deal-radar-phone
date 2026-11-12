/* Offline support: the app shell is cached at install. Only same-origin GETs are handled; requests to GitHub are never touched.
   The screens themselves arrive encrypted from your PC and are cached inside the app's own (encrypted) storage. */
const BUILD = '7ed0c6d99e'; const CORE = 'dr-core-' + BUILD;
const SHELL = ['index.html', 'loader.js', 'manifest.webmanifest', 'icon-180.png', 'icon-192.png'];
self.addEventListener('install', (e) => { e.waitUntil(caches.open(CORE).then((c) => Promise.all(SHELL.map((u) => c.add(new Request(u, { cache: 'reload' }))))).then(() => self.skipWaiting())); });
self.addEventListener('activate', (e) => { e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k.startsWith('dr-core-') && k !== CORE).map((k) => caches.delete(k)))).then(() => self.clients.claim())); });
self.addEventListener('fetch', (e) => {
  const req = e.request; if (req.method !== 'GET') return; const url = new URL(req.url); if (url.origin !== location.origin) return;
  if (req.mode === 'navigate') { e.respondWith(fetch(req).catch(() => caches.match('index.html'))); return; }
  e.respondWith(caches.match(req, { ignoreSearch: true }).then((hit) => hit || fetch(req)));
});
