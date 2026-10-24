// 離線殼層快取：先抓網路（拿到最新版），失敗才用快取
const CACHE = 'cladue-v1.1.1';
const SHELL = ['./', 'index.html', 'app.js', 'lib/mqtt.min.js', 'lib/qrcode.js', 'manifest.webmanifest', 'icon-192.png', 'icon-512.png', 'badge-96.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(ks => Promise.all(ks.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (e.request.method !== 'GET' || url.origin !== location.origin) return;
  e.respondWith(
    fetch(e.request).then(r => {
      if (r.ok) { const copy = r.clone(); caches.open(CACHE).then(c => c.put(e.request, copy)); }
      return r;
    }).catch(() => caches.match(e.request, { ignoreSearch: true }).then(r => r || caches.match('index.html')))
  );
});
// 點通知：已開著就切到該對話，沒開就開啟 App 並帶上對話 id
self.addEventListener('notificationclick', e => {
  e.notification.close();
  const conv = e.notification.data?.conv;
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => {
    const c = cs.find(x => x.focused) || cs[0];
    if (c) {
      if (conv) c.postMessage({ type: 'open', conv });
      return c.focus();
    }
    return self.clients.openWindow(conv ? './#conv=' + encodeURIComponent(conv) : './');
  }));
});
