// 離線殼層快取：先抓網路（拿到最新版），失敗才用快取
const CACHE = 'cladue-v1.2.0';
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

/* ---------- 推播：App 被暫停或關閉時，由推播伺服器叫醒 ----------
 * 推播內容是「已端對端加密」的訊息，在這裡用本機 IndexedDB 裡的金鑰解密、存進聊天紀錄，再跳通知
 */
const te = new TextEncoder(), td = new TextDecoder();
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const sha256 = async d => new Uint8Array(await crypto.subtle.digest('SHA-256', typeof d === 'string' ? te.encode(d) : d));
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
// Safari（iPhone / iPad / Mac）規定每次推播都必須顯示通知，否則會被取消推播權限
const STRICT = /Safari/.test(navigator.userAgent) && !/Chrom|Edg|Android/.test(navigator.userAgent);

const req = r => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('cladue', 1);
    r.onupgradeneeded = () => r.transaction.abort();  // App 還沒初始化過，不要建立空資料庫
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function dec(key, env) {
  try {
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.ct));
    return JSON.parse(td.decode(pt));
  } catch { return null; }
}
async function roomKey(conv) {
  const base = await crypto.subtle.importKey('raw', te.encode(conv.pass), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt: te.encode('cladue|' + conv.roomId), iterations: 120000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
async function pairKey(me, conv) {
  const priv = await crypto.subtle.importKey('jwk', { ...me.privJwk, key_ops: ['deriveBits'] }, ECDH, false, ['deriveBits']);
  const pub = await crypto.subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: conv.pubJwk.x, y: conv.pubJwk.y }, ECDH, false, []);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256));
  const raw = await sha256(new Uint8Array([...bits, ...te.encode('cladue-pair')]));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);
}
async function setBadge(db) {
  if (!self.navigator.setAppBadge) return;
  const cs = await req(db.transaction('convs').objectStore('convs').getAll());
  const n = cs.reduce((a, c) => a + (c.status === 'declined' || c.muted ? 0 : (c.unread || 0)), 0);
  await (n ? self.navigator.setAppBadge(n) : self.navigator.clearAppBadge()).catch(() => {});
}
// 回傳要顯示的通知內容；null = 不認得的推播
async function handlePush(d) {
  if (!d || typeof d !== 'object') return null;
  const db = await idb();
  try {
    const get = (st, k) => req(db.transaction(st).objectStore(st).get(k));
    const me = await get('kv', 'identity');
    if (!me) return null;
    const preview = ((await get('kv', 'settings')) || {}).preview !== false;
    const who = String(d.name || '').slice(0, 40) || '新朋友';
    if (d.t === 'freq') return { title: who, body: '想加你為好友', conv: 'f:' + d.from, preview: true };
    if (d.t === 'facc') return { title: who, body: '已接受你的好友邀請', conv: 'f:' + d.from, preview: true };
    let conv, key = null;
    if (d.t === 'r') {
      conv = (await req(db.transaction('convs').objectStore('convs').getAll())).find(c => c.type === 'room' && c.topic === d.topic);
      if (conv && d.iv) key = await roomKey(conv);
    } else if (d.t === 'e') {
      conv = await get('convs', 'f:' + d.from);
      if (conv?.status !== 'friend') conv = null;
      if (conv && d.iv) key = await pairKey(me, conv);
    }
    if (!conv) return null;
    const isRoom = conv.type === 'room';
    const out = { title: isRoom ? '# ' + conv.title : conv.name, conv: conv.id, muted: !!conv.muted, preview };
    const m = key && await dec(key, d);
    if (!m || typeof m.id !== 'string') return { ...out, body: '傳來新訊息' };  // 訊息太長沒放進推播：打開 App 後會同步
    const ts = +m.ts || Date.now();
    let rec;
    if (isRoom && m.k === 'msg' && typeof m.text === 'string' && m.from !== me.code)
      rec = { id: m.id, from: m.from, name: String(m.name || '').slice(0, 40), ts, text: m.text.slice(0, 4000) };
    else if (!isRoom && m.k === 'dm' && typeof m.text === 'string')
      rec = { id: m.id, from: conv.code, name: conv.name, ts, text: m.text.slice(0, 4000) };
    else if (!isRoom && m.k === 'inv' && typeof m.roomId === 'string' && typeof m.pass === 'string')
      rec = { id: m.id, kind: 'inv', from: conv.code, name: conv.name, ts, roomId: m.roomId, pass: m.pass, title: String(m.title || m.roomId).slice(0, 60), text: '' };
    if (!rec) return null;
    rec.conv = conv.id;
    const body = rec.kind === 'inv' ? `邀請你加入聊天室「${rec.title}」` : (isRoom ? rec.name + '：' : '') + rec.text;
    if (await get('msgs', rec.id)) return { ...out, body, ts, dup: true };  // App 在背景時已經收到過
    // 存進聊天紀錄並累加未讀（跟 App 的 addMsg 相同格式）
    const t = db.transaction(['msgs', 'convs'], 'readwrite');
    t.objectStore('msgs').put(rec);
    const cs = t.objectStore('convs');
    cs.get(conv.id).onsuccess = e => {
      const c = e.target.result;
      if (!c) return;
      if (!c.lastTs || ts >= c.lastTs) { c.lastTs = ts; c.last = rec.kind === 'inv' ? `［聊天室邀請］${rec.title}` : body; }
      c.unread = (c.unread || 0) + 1;
      out.unread = c.unread;
      cs.put(c);
    };
    await new Promise((res, rej) => { t.oncomplete = res; t.onerror = () => rej(t.error); });
    await setBadge(db);
    return { ...out, body, ts };
  } finally { db.close(); }
}
async function onPush(d) {
  const show = (title, opts) => self.registration.showNotification(title, { icon: 'icon-192.png', badge: 'badge-96.png', ...opts });
  const wins = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  if (wins.some(c => c.visibilityState === 'visible')) {
    // App 正開著：訊息會從即時連線進來，不用重複通知
    if (!STRICT) return;
    await show('Cladue 聊天', { tag: 'cladue-fg', silent: true });
    (await self.registration.getNotifications({ tag: 'cladue-fg' })).forEach(n => n.close());
    return;
  }
  let r = null;
  try { r = await handlePush(d); } catch (err) { console.warn('push', err); }
  for (const c of wins) c.postMessage({ type: 'sync' });  // 背景中的頁面重新讀取資料
  if (r && !r.muted && !r.dup) {
    return show(r.title, {
      body: (r.unread > 1 ? `（${r.unread} 則未讀）` : '') + (r.preview ? r.body : '傳來一則新訊息').slice(0, 120),
      tag: r.conv, renotify: true, timestamp: r.ts || Date.now(), data: { conv: r.conv },
    });
  }
  if (!STRICT) return;
  if (r) return show(r.title, { body: r.preview ? r.body.slice(0, 120) : '傳來一則新訊息', tag: r.conv, silent: true, data: { conv: r.conv } });
  return show('Cladue 聊天', { body: '有新的活動', tag: 'cladue', silent: true });
}
self.addEventListener('push', e => {
  let d = null;
  try { d = e.data?.json(); } catch {}
  e.waitUntil(onPush(d));
});
// 推播訂閱被瀏覽器更換時，通知頁面重新登記
self.addEventListener('pushsubscriptionchange', e => {
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => cs.forEach(c => c.postMessage({ type: 'resub' }))));
});
