/* Cladue 聊天 — 端對端加密、資料只存本機的文字聊天室
 * 傳輸：公共 MQTT over WebSocket（只轉送密文，不保存）
 * 儲存：瀏覽器 IndexedDB（只在自己的裝置）
 */
'use strict';
(() => {
const APP_VER = '1.1.0';
const NS = 'cladue/v1';
const DEFAULT_BROKERS = ['wss://broker.emqx.io:8084/mqtt', 'wss://test.mosquitto.org:8081/mqtt'];
const RESEND_MS = 30e3;        // 未確認的好友邀請 / 私訊 / 聊天室邀請重送間隔
const PING_MS = 45e3;          // 聊天室在線心跳
const ONLINE_TTL = 120e3;      // 超過此時間沒心跳視為離線
const OUTBOX_TTL = 7 * 864e5;  // 未送達項目保留 7 天
const SYNC_MAX = 300;          // 補歷史訊息上限
const MAX_LEN = 4000;

const te = new TextEncoder(), td = new TextDecoder();
const subtle = crypto.subtle;
const $ = (s, el = document) => el.querySelector(s);
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const rid = (bytes = 8) => [...crypto.getRandomValues(new Uint8Array(bytes))].map(b => b.toString(16).padStart(2, '0')).join('');
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const sha256 = async data => new Uint8Array(await subtle.digest('SHA-256', typeof data === 'string' ? te.encode(data) : data));
function b64(u8) { let s = ''; for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000)); return btoa(s); }
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const b64u = str => b64(te.encode(str)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const unb64u = s => td.decode(unb64(s.replace(/-/g, '+').replace(/_/g, '/')));
const B32 = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function b32(u8) { let bits = 0, val = 0, out = ''; for (const b of u8) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } } return out; }
const fmtCode = c => (c || '').match(/.{1,4}/g)?.join('-') || '';
const normCode = s => String(s || '').toUpperCase().replace(/[^A-Z0-9]/g, '');
const isCode = c => typeof c === 'string' && /^[A-HJ-NP-Z2-9]{12}$/.test(c);
const inboxTopic = code => `${NS}/u/${code}`;
const now = () => Date.now();

/* ---------- IndexedDB ---------- */
const db = {
  h: null,
  open() {
    return new Promise((res, rej) => {
      const r = indexedDB.open('cladue', 1);
      r.onupgradeneeded = () => {
        const d = r.result;
        d.createObjectStore('kv');
        d.createObjectStore('convs', { keyPath: 'id' });
        d.createObjectStore('msgs', { keyPath: 'id' }).createIndex('conv_ts', ['conv', 'ts']);
        d.createObjectStore('outbox', { keyPath: 'id' });
      };
      r.onsuccess = () => { this.h = r.result; res(); };
      r.onerror = () => rej(r.error);
    });
  },
  tx(store, mode, fn) {
    return new Promise((res, rej) => {
      const t = this.h.transaction(store, mode);
      let out;
      const r = fn(t.objectStore(store));
      if (r) r.onsuccess = () => { out = r.result; };
      t.oncomplete = () => res(out);
      t.onerror = () => rej(t.error);
    });
  },
  get(st, k) { return this.tx(st, 'readonly', s => s.get(k)); },
  put(st, v, k) { return this.tx(st, 'readwrite', s => (k === undefined ? s.put(v) : s.put(v, k))); },
  del(st, k) { return this.tx(st, 'readwrite', s => s.delete(k)); },
  all(st) { return this.tx(st, 'readonly', s => s.getAll()); },
  keys(st) { return this.tx(st, 'readonly', s => s.getAllKeys()); },
  convMsgs(conv, since = -1) {
    return this.tx('msgs', 'readonly', s => s.index('conv_ts').getAll(IDBKeyRange.bound([conv, since], [conv, Infinity], true, false)));
  },
  delConvMsgs(conv) {
    return this.tx('msgs', 'readwrite', s => {
      const r = s.index('conv_ts').openKeyCursor(IDBKeyRange.bound([conv, -Infinity], [conv, Infinity]));
      r.onsuccess = () => { const c = r.result; if (c) { s.delete(c.primaryKey); c.continue(); } };
    });
  },
  clearAll() { return Promise.all(['kv', 'convs', 'msgs', 'outbox'].map(st => this.tx(st, 'readwrite', s => s.clear()))); },
};

/* ---------- 狀態 ---------- */
const S = {
  me: null, priv: null, settings: null,
  convs: new Map(), active: null,
  msgIds: new Set(),
  roomKeys: new Map(), pairKeys: new Map(),
  online: new Map(),         // convId -> Map(code -> {name, t})
  answered: new Set(),       // 已有人回應的 sync 請求
  seen: new Map(),           // 原始封包去重
  unreadMark: null,          // {conv, n}：開啟對話時要畫「以下為未讀訊息」的位置
};
let chain = Promise.resolve();
const serial = fn => (chain = chain.then(fn).catch(e => console.error(e)));

/* ---------- 加密 ---------- */
const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
async function codeOf(jwk) { return b32(await sha256(`${jwk.x}.${jwk.y}`)).slice(0, 12); }
async function enc(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(JSON.stringify(obj))));
  return { iv: b64(iv), ct: b64(ct) };
}
async function dec(key, env) {
  try {
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv: unb64(env.iv) }, key, unb64(env.ct));
    return JSON.parse(td.decode(pt));
  } catch { return null; }
}
async function roomMeta(roomId, pass) {
  const h = hex(await sha256(`room|${roomId}|${pass}`)).slice(0, 32);
  return { id: 'r:' + h, topic: `${NS}/r/${h}` };
}
async function roomKey(conv) {
  if (S.roomKeys.has(conv.id)) return S.roomKeys.get(conv.id);
  const base = await subtle.importKey('raw', te.encode(conv.pass), 'PBKDF2', false, ['deriveKey']);
  const k = await subtle.deriveKey({ name: 'PBKDF2', salt: te.encode('cladue|' + conv.roomId), iterations: 120000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  S.roomKeys.set(conv.id, k);
  return k;
}
async function pairKey(conv) {
  if (S.pairKeys.has(conv.id)) return S.pairKeys.get(conv.id);
  const pub = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: conv.pubJwk.x, y: conv.pubJwk.y }, ECDH, false, []);
  const bits = new Uint8Array(await subtle.deriveBits({ name: 'ECDH', public: pub }, S.priv, 256));
  const raw = await sha256(new Uint8Array([...bits, ...te.encode('cladue-pair')]));
  const k = await subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  S.pairKeys.set(conv.id, k);
  return k;
}

/* ---------- 身分（每台裝置唯一碼） ---------- */
async function initIdentity() {
  let id = await db.get('kv', 'identity');
  if (!id) {
    const kp = await subtle.generateKey(ECDH, true, ['deriveBits']);
    const pubJwk = await subtle.exportKey('jwk', kp.publicKey);
    const privJwk = await subtle.exportKey('jwk', kp.privateKey);
    id = { pubJwk: { x: pubJwk.x, y: pubJwk.y }, privJwk, code: await codeOf(pubJwk), name: '', created: now() };
    await db.put('kv', id, 'identity');
  }
  S.me = id;
  S.priv = await subtle.importKey('jwk', { ...id.privJwk, key_ops: ['deriveBits'] }, ECDH, false, ['deriveBits']);
}

/* ---------- 網路（同時連多台中繼，互相備援） ---------- */
const net = {
  clients: [],
  start() {
    for (const url of S.settings.brokers) {
      let c;
      try {
        c = mqtt.connect(url, { clientId: 'cl_' + rid(8), keepalive: 30, reconnectPeriod: 5000, connectTimeout: 10000, clean: true });
      } catch (e) { console.warn(url, e); continue; }
      c._url = url;
      c.on('connect', () => { c.subscribe(this.topics(), { qos: 0 }); updateStatus(); onConnected(); });
      c.on('close', updateStatus);
      c.on('offline', updateStatus);
      c.on('error', e => console.warn(url, e?.message));
      c.on('message', (topic, buf) => onRaw(topic, buf.toString()));
      this.clients.push(c);
    }
    updateStatus();
  },
  stop() { for (const c of this.clients) c.end(true); this.clients = []; },
  topics() { return [inboxTopic(S.me.code), ...[...S.convs.values()].filter(c => c.type === 'room').map(c => c.topic)]; },
  sub(t) { for (const c of this.clients) if (c.connected) c.subscribe(t, { qos: 0 }); },
  unsub(t) { for (const c of this.clients) if (c.connected) c.unsubscribe(t); },
  pub(topic, obj) {
    const s = JSON.stringify(obj);
    let ok = false;
    for (const c of this.clients) if (c.connected) { c.publish(topic, s, { qos: 0 }); ok = true; }
    return ok;
  },
  count() { return this.clients.filter(c => c.connected).length; },
};

let connTimer = 0;
function onConnected() {
  clearTimeout(connTimer);
  connTimer = setTimeout(() => serial(async () => {
    for (const c of S.convs.values()) if (c.type === 'room') await roomHello(c);
    await flushOutbox();
  }), 800);
}

function onRaw(topic, s) {
  const dk = topic + '|' + s.length + '|' + s.slice(-48);
  if (S.seen.has(dk)) return;
  S.seen.set(dk, 1);
  if (S.seen.size > 3000) S.seen.delete(S.seen.keys().next().value);
  let o;
  try { o = JSON.parse(s); } catch { return; }
  if (!o || o.v !== 1) return;
  serial(async () => {
    if (topic === inboxTopic(S.me.code)) return onInbox(o);
    const conv = [...S.convs.values()].find(c => c.type === 'room' && c.topic === topic);
    if (!conv || !o.iv) return;
    const m = await dec(await roomKey(conv), o);
    if (m) await onRoom(conv, m);
  });
}

/* ---------- 待送佇列 ---------- */
async function queue(item) {
  item.created = item.created || now();
  await db.put('outbox', item);
  await sendItem(item);
}
async function sendItem(item) {
  if (!net.count()) return false;
  if (item.kind === 'freq') {
    return net.pub(inboxTopic(item.to), { v: 1, k: 'freq', from: S.me.code, pub: S.me.pubJwk, name: S.me.name });
  }
  if (item.kind === 'room') {
    const conv = S.convs.get(item.conv);
    if (!conv) { await db.del('outbox', item.id); return false; }
    const ok = net.pub(conv.topic, { v: 1, ...(await enc(await roomKey(conv), item.body)) });
    if (ok) { await db.del('outbox', item.id); await setMsgState(item.id, 'sent'); }
    return ok;
  }
  // dm / inv：用好友間的配對金鑰加密，等對方回 ack 才移出佇列
  const conv = S.convs.get('f:' + item.to);
  if (!conv || conv.status !== 'friend') return false;
  return net.pub(inboxTopic(item.to), { v: 1, k: 'e', from: S.me.code, ...(await enc(await pairKey(conv), item.body)) });
}
async function flushOutbox() {
  for (const it of await db.all('outbox')) {
    if (now() - it.created > OUTBOX_TTL) { await db.del('outbox', it.id); continue; }
    await sendItem(it);
  }
}
async function sendInner(code, body) {
  const conv = S.convs.get('f:' + code);
  if (!conv || conv.status !== 'friend' || !net.count()) return;
  net.pub(inboxTopic(code), { v: 1, k: 'e', from: S.me.code, ...(await enc(await pairKey(conv), body)) });
}

/* ---------- 訊息儲存 ---------- */
async function addMsg(conv, m, opts = {}) {
  if (S.msgIds.has(m.id)) return false;
  S.msgIds.add(m.id);
  m.conv = conv.id;
  await db.put('msgs', m);
  const mine = m.from === S.me.code;
  if (!conv.lastTs || m.ts >= conv.lastTs) {
    conv.lastTs = m.ts;
    conv.last = m.kind === 'inv' ? `［聊天室邀請］${m.title}` : (m.sys ? `${m.name || ''} ${m.text}` : (conv.type === 'room' && !mine ? `${m.name}：` : '') + m.text);
  }
  const viewing = S.active === conv.id && !document.hidden && document.hasFocus();
  if (!mine && !m.sys && !viewing && !opts.quiet) conv.unread = (conv.unread || 0) + 1;
  await saveConv(conv);
  if (S.active === conv.id) { if (!opts.batch) appendMsg(m); }
  if (!mine && !m.sys && !opts.quiet && !opts.batch && !viewing) notify(conv, m);
  if (!opts.batch) renderList();
  return true;
}
async function setMsgState(id, state) {
  const m = await db.get('msgs', id);
  if (!m || m.state === 'acked') return;
  m.state = state;
  await db.put('msgs', m);
  const el = document.querySelector(`[data-mid="${id}"] .st`);
  if (el) el.textContent = stateMark(m);
}
const stateMark = m => (m.from !== S.me.code || m.sys) ? '' : m.state === 'acked' ? '✓✓' : m.state === 'sent' ? '✓' : '🕓';
async function saveConv(conv) { S.convs.set(conv.id, conv); await db.put('convs', conv); }
async function sysMsg(conv, text, ts = now()) {
  await addMsg(conv, { id: 's' + rid(8), from: '', name: '', ts, text, sys: true }, { quiet: true });
}

/* ---------- 聊天室 ---------- */
async function joinRoom(roomId, pass, title) {
  roomId = String(roomId || '').trim().toLowerCase();
  pass = String(pass || '');
  if (!roomId || !pass) return toast('請輸入聊天室代號與密碼');
  const meta = await roomMeta(roomId, pass);
  let conv = S.convs.get(meta.id);
  if (!conv) {
    conv = { id: meta.id, type: 'room', roomId, pass, topic: meta.topic, title: (title || '').trim() || roomId, created: now(), lastTs: 0, aliveTs: 0 };
    await saveConv(conv);
    net.sub(conv.topic);
    await sysMsg(conv, '你已加入聊天室');
    await sendRoomMsg(conv, '加入了聊天室', true);
    serial(() => roomHello(conv));
  }
  openConv(conv.id);
}
async function roomHello(conv) {
  if (!net.count()) return;
  const key = await roomKey(conv);
  const rq = rid(6);
  const since = Math.max(-1, (conv.aliveTs || 0) - 5 * 60e3);
  net.pub(conv.topic, { v: 1, ...(await enc(key, { k: 'sync', rq, from: S.me.code, name: S.me.name, since })) });
  net.pub(conv.topic, { v: 1, ...(await enc(key, { k: 'ping', hello: true, from: S.me.code, name: S.me.name })) });
}
async function sendRoomMsg(conv, text, sys = false) {
  const m = { id: rid(8), from: S.me.code, name: S.me.name, ts: now(), text, sys: sys || undefined, state: 'pending' };
  await addMsg(conv, { ...m });
  await queue({ id: m.id, kind: 'room', conv: conv.id, body: { k: 'msg', id: m.id, from: m.from, name: m.name, ts: m.ts, text, sys: m.sys } });
}
async function leaveRoom(conv) {
  await sendRoomMsg(conv, '離開了聊天室', true);
  net.pub(conv.topic, { v: 1, ...(await enc(await roomKey(conv), { k: 'bye', from: S.me.code })) });
  net.unsub(conv.topic);
  await removeConv(conv);
}
async function removeConv(conv) {
  S.convs.delete(conv.id);
  await db.del('convs', conv.id);
  await db.delConvMsgs(conv.id);
  for (const it of await db.all('outbox')) if (it.conv === conv.id || (conv.code && it.to === conv.code)) await db.del('outbox', it.id);
  if (S.active === conv.id) closeConv();
  renderList();
}
function touchOnline(conv, code, name) {
  if (!code || code === S.me.code) return;
  if (!S.online.has(conv.id)) S.online.set(conv.id, new Map());
  S.online.get(conv.id).set(code, { name, t: now() });
  if (S.active === conv.id) renderHeadSub();
}
function onlineList(conv) {
  const m = S.online.get(conv.id);
  if (!m) return [];
  for (const [k, v] of m) if (now() - v.t > ONLINE_TTL) m.delete(k);
  return [...m.entries()].map(([code, v]) => ({ code, name: v.name }));
}
async function onRoom(conv, m) {
  if (typeof m.from !== 'string' || m.from === S.me.code) return;
  const name = String(m.name || '').slice(0, 40);
  if (m.k === 'msg') {
    touchOnline(conv, m.from, name);
    if (typeof m.text !== 'string' || typeof m.id !== 'string') return;
    await addMsg(conv, { id: m.id, from: m.from, name, ts: +m.ts || now(), text: m.text.slice(0, MAX_LEN), sys: m.sys ? true : undefined });
  } else if (m.k === 'ping') {
    touchOnline(conv, m.from, name);
    if (m.hello) setTimeout(() => serial(async () => {
      net.pub(conv.topic, { v: 1, ...(await enc(await roomKey(conv), { k: 'ping', from: S.me.code, name: S.me.name })) });
    }), 300 + Math.random() * 1500);
  } else if (m.k === 'bye') {
    S.online.get(conv.id)?.delete(m.from);
    if (S.active === conv.id) renderHeadSub();
  } else if (m.k === 'sync') {
    touchOnline(conv, m.from, name);
    const since = typeof m.since === 'number' ? m.since : -1;
    setTimeout(() => serial(async () => {
      if (S.answered.has(m.rq)) return;  // 別人已經回應了
      const list = (await db.convMsgs(conv.id, since)).filter(x => !x.kind && (!x.sys || x.from)).slice(-SYNC_MAX)
        .map(x => ({ id: x.id, from: x.from, name: x.name, ts: x.ts, text: x.text, sys: x.sys }));
      if (!list.length) return;
      const key = await roomKey(conv);
      for (let i = 0; i < list.length; i += 25)
        net.pub(conv.topic, { v: 1, ...(await enc(key, { k: 'hist', rq: m.rq, from: S.me.code, msgs: list.slice(i, i + 25) })) });
    }), 200 + Math.random() * 1200);
  } else if (m.k === 'hist') {
    S.answered.add(m.rq);
    if (!Array.isArray(m.msgs)) return;
    let added = 0, fresh = 0;
    for (const x of m.msgs) {
      if (!x || typeof x.id !== 'string' || typeof x.text !== 'string' || typeof x.from !== 'string') continue;
      if (await addMsg(conv, { id: x.id, from: x.from, name: String(x.name || '').slice(0, 40), ts: +x.ts || 0, text: x.text.slice(0, MAX_LEN), sys: x.sys ? true : undefined, state: 'sent' }, { batch: true, quiet: x.from === S.me.code })) {
        added++;
        if (x.from !== S.me.code && !x.sys) fresh++;
      }
    }
    if (added) { if (S.active === conv.id) renderMsgs(); renderList(); }
    // 離線期間補回來的訊息：彙整成一則通知
    if (fresh && !(S.active === conv.id && !document.hidden && document.hasFocus())) notify(conv, { text: `補收到 ${fresh} 則新訊息` });
  }
}

/* ---------- 好友 ---------- */
async function addFriend(input) {
  const code = normCode(input);
  if (!isCode(code)) return toast('ID 碼格式不正確（12 碼）'), false;
  if (code === S.me.code) return toast('這是你自己的 ID 碼'), false;
  let conv = S.convs.get('f:' + code);
  if (conv && conv.status === 'friend') { openConv(conv.id); return true; }
  if (conv && conv.status === 'pending-in') { await acceptFriend(conv); return true; }
  conv = { id: 'f:' + code, type: 'friend', code, name: fmtCode(code), status: 'pending-out', created: now(), lastTs: now() };
  await saveConv(conv);
  await queue({ id: 'freq:' + code, kind: 'freq', to: code });
  renderList();
  openConv(conv.id);
  toast('已送出好友邀請');
  return true;
}
async function acceptFriend(conv) {
  conv.status = 'friend';
  await saveConv(conv);
  await db.del('outbox', 'freq:' + conv.code);
  net.pub(inboxTopic(conv.code), { v: 1, k: 'facc', from: S.me.code, pub: S.me.pubJwk, name: S.me.name });
  await sysMsg(conv, '你們已成為好友');
  renderList();
  openConv(conv.id);
}
async function declineFriend(conv) {
  conv.status = 'declined';
  conv.unread = 0;
  await saveConv(conv);
  renderList();
  if (S.active === conv.id) closeConv();
}
async function validPeer(o) {
  return isCode(o.from) && o.pub && typeof o.pub.x === 'string' && typeof o.pub.y === 'string' && (await codeOf(o.pub)) === o.from;
}
async function onInbox(o) {
  if (o.k === 'freq') {
    if (!(await validPeer(o))) return;
    const name = String(o.name || '').slice(0, 40) || fmtCode(o.from);
    let conv = S.convs.get('f:' + o.from);
    if (conv?.status === 'declined') return;
    if (conv?.status === 'friend') {
      // 對方沒收到我的同意，再回一次
      net.pub(inboxTopic(o.from), { v: 1, k: 'facc', from: S.me.code, pub: S.me.pubJwk, name: S.me.name });
      return;
    }
    if (conv?.status === 'pending-out') {  // 雙方互加 → 直接成為好友
      Object.assign(conv, { pubJwk: o.pub, name });
      return acceptFriend(conv);
    }
    if (conv?.status === 'pending-in') return;
    conv = { id: 'f:' + o.from, type: 'friend', code: o.from, pubJwk: o.pub, name, status: 'pending-in', created: now(), lastTs: now(), unread: 1 };
    await saveConv(conv);
    renderList();
    notify(conv, { text: '想加你為好友' });
  } else if (o.k === 'facc') {
    const conv = S.convs.get('f:' + o.from);
    if (!conv || conv.status !== 'pending-out' || !(await validPeer(o))) return;
    Object.assign(conv, { pubJwk: o.pub, name: String(o.name || '').slice(0, 40) || fmtCode(o.from), status: 'friend' });
    await saveConv(conv);
    await db.del('outbox', 'freq:' + conv.code);
    await sysMsg(conv, '對方已接受，你們已成為好友');
    renderList();
    if (S.active === conv.id) renderChat();
    notify(conv, { text: '已接受你的好友邀請' });
    await flushOutbox();
  } else if (o.k === 'e') {
    const conv = S.convs.get('f:' + o.from);
    if (!conv || conv.status !== 'friend' || !o.iv) return;
    const m = await dec(await pairKey(conv), o);
    if (!m) return;
    if (m.name && m.name !== conv.name) { conv.name = String(m.name).slice(0, 40); await saveConv(conv); renderList(); }
    if (m.k === 'ack') {
      await db.del('outbox', m.id);
      await setMsgState(m.id, 'acked');
    } else if (m.k === 'dm' && typeof m.text === 'string') {
      await sendInner(conv.code, { k: 'ack', id: m.id, name: S.me.name });
      await addMsg(conv, { id: m.id, from: conv.code, name: conv.name, ts: +m.ts || now(), text: m.text.slice(0, MAX_LEN) });
    } else if (m.k === 'inv' && typeof m.roomId === 'string' && typeof m.pass === 'string') {
      await sendInner(conv.code, { k: 'ack', id: m.id, name: S.me.name });
      await addMsg(conv, { id: m.id, kind: 'inv', from: conv.code, name: conv.name, ts: +m.ts || now(), roomId: m.roomId, pass: m.pass, title: String(m.title || m.roomId).slice(0, 60), text: '' });
    }
  }
}
async function sendDm(conv, text) {
  const m = { id: rid(8), from: S.me.code, name: S.me.name, ts: now(), text, state: 'pending' };
  await addMsg(conv, { ...m });
  await queue({ id: m.id, kind: 'dm', to: conv.code, body: { k: 'dm', id: m.id, ts: m.ts, text, name: S.me.name } });
  if (net.count()) await setMsgState(m.id, 'sent');
}
async function inviteFriend(friendConv, room) {
  const id = rid(8);
  const m = { id, kind: 'inv', from: S.me.code, name: S.me.name, ts: now(), roomId: room.roomId, pass: room.pass, title: room.title, text: '', state: 'pending' };
  await addMsg(friendConv, m);
  await queue({ id, kind: 'inv', to: friendConv.code, body: { k: 'inv', id, ts: m.ts, roomId: room.roomId, pass: room.pass, title: room.title, name: S.me.name } });
  if (net.count()) await setMsgState(id, 'sent');
}

/* ---------- 連結 ---------- */
const baseUrl = () => location.origin + location.pathname;
const addLink = () => `${baseUrl()}#add=${S.me.code}`;
const joinLink = room => `${baseUrl()}#join=${b64u(JSON.stringify({ r: room.roomId, p: room.pass, t: room.title }))}`;
function handleHash() {
  const h = location.hash.slice(1);
  if (!h) return;
  history.replaceState(null, '', baseUrl());
  const p = new URLSearchParams(h);
  if (p.get('conv')) return openConv(p.get('conv'));  // 從通知開啟
  if (p.get('add')) return openAddFriend(p.get('add'));
  if (p.get('join')) {
    let j;
    try { j = JSON.parse(unb64u(p.get('join'))); } catch { return toast('邀請連結無效'); }
    if (!j || !j.r || !j.p) return toast('邀請連結無效');
    modal(`<h3>加入聊天室</h3><p>你收到聊天室「<b>${esc(j.t || j.r)}</b>」的邀請連結，要加入嗎？</p>
      <div class="acts"><button class="btn" data-close>取消</button><button class="btn pri" id="ok">加入</button></div>`,
    (el, close) => { $('#ok', el).onclick = () => { close(); joinRoom(j.r, j.p, j.t); }; });
  }
}
async function share(title, url) {
  if (navigator.share) {
    try { await navigator.share({ title, text: title, url }); return; } catch (e) { if (e.name === 'AbortError') return; }
  }
  copy(url);
}
async function copy(text) {
  try { await navigator.clipboard.writeText(text); }
  catch { const t = document.createElement('textarea'); t.value = text; document.body.append(t); t.select(); document.execCommand('copy'); t.remove(); }
  toast('已複製連結');
}
function qrSvg(text) {
  const q = qrcode(0, 'M');
  q.addData(text);
  q.make();
  return q.createSvgTag({ cellSize: 4, margin: 2, scalable: true });
}

/* ---------- 通知 ---------- */
const canNotify = () => 'Notification' in window && Notification.permission === 'granted';
const isIOS = /iP(hone|ad|od)/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
const standalone = () => matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
function notify(conv, m) {
  updateBadge();
  if (conv.muted) return;
  const title = conv.type === 'room' ? `# ${conv.title}` : conv.name;
  const preview = S.settings.preview !== false;
  const body = !preview ? '傳來一則新訊息'
    : (conv.type === 'room' && m.name ? m.name + '：' : '') + (m.kind === 'inv' ? `邀請你加入聊天室「${m.title}」` : m.text);
  // App 在前景：不跳系統通知，改用可點的提示條
  if (!document.hidden && document.hasFocus()) {
    if (S.active !== conv.id) toast(`${title}｜${body}`.slice(0, 80), () => openConv(conv.id));
    return;
  }
  if (!canNotify()) return;
  const n = conv.unread || 0;
  const opts = {
    body: (n > 1 ? `（${n} 則未讀）` : '') + body.slice(0, 120),
    tag: conv.id, renotify: true, timestamp: m.ts || now(),
    icon: 'icon-192.png', badge: 'badge-96.png', data: { conv: conv.id },
  };
  if (navigator.serviceWorker?.controller) navigator.serviceWorker.ready.then(r => r.showNotification(title, opts)).catch(() => {});
  else try {
    const nt = new Notification(title, opts);
    nt.onclick = () => { window.focus(); openConv(conv.id); nt.close(); };
  } catch {}
}
function clearNotifs(id) {
  navigator.serviceWorker?.ready.then(r => r.getNotifications({ tag: id })).then(ns => ns.forEach(n => n.close())).catch(() => {});
}
async function enableNotify() {
  if (!('Notification' in window)) {
    toast(isIOS && !standalone() ? 'iPhone 請先「加入主畫面」，從主畫面開啟後才能開啟通知' : '此瀏覽器不支援通知');
    return 'unsupported';
  }
  const p = await Notification.requestPermission();
  toast(p === 'granted' ? '已開啟通知' : '未允許通知，可到瀏覽器 / 系統設定中開啟');
  renderList();
  return p;
}
// 未讀總數（不含已拒絕、已靜音的對話）
const unreadTotal = (except = null) => [...S.convs.values()]
  .reduce((a, c) => a + (c.status === 'declined' || c.muted || c.id === except ? 0 : (c.unread || 0)), 0);
const badgeNum = n => (n > 99 ? '99+' : n);
function updateBadge() {
  const n = unreadTotal();
  document.title = n ? `(${badgeNum(n)}) Cladue 聊天` : 'Cladue 聊天';
  // App 圖示上的數字（安裝成 App 後：Windows / macOS / Android Chrome、iOS 16.4+ 主畫面 App）
  if ('setAppBadge' in navigator) (n ? navigator.setAppBadge(n) : navigator.clearAppBadge()).catch(() => {});
  // 手機版聊天畫面左上「‹」顯示其他對話的未讀數
  const back = $('#backBtn');
  if (back) { const k = unreadTotal(S.active); back.innerHTML = '‹' + (k ? `<span class="badge">${badgeNum(k)}</span>` : ''); }
}
function markActiveRead() {
  const c = S.convs.get(S.active);
  if (!c || document.hidden) return;
  clearNotifs(c.id);
  if (!c.unread) return;
  S.unreadMark = { conv: c.id, n: c.unread };
  c.unread = 0;
  saveConv(c);
  renderList();
  renderMsgs();
}

/* ---------- UI ---------- */
const COLORS = ['#4f6bed', '#e0607e', '#1fa36a', '#d9822b', '#8e5bd8', '#1b9bb8', '#c2563a', '#5a7d2a'];
function avatar(text, seed, cls = '') {
  let h = 0;
  for (const ch of String(seed)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return `<div class="av ${cls}" style="background:${COLORS[h % COLORS.length]}">${esc([...String(text || '?').trim()][0] || '?')}</div>`;
}
function fmtTime(ts) {
  const d = new Date(ts), n = new Date();
  if (d.toDateString() === n.toDateString()) return d.toTimeString().slice(0, 5);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}
let toastTimer = 0;
function toast(text, onClick) {
  document.querySelector('.toast')?.remove();
  const t = document.createElement('div');
  t.className = 'toast' + (onClick ? ' click' : '');
  t.textContent = text;
  if (onClick) t.onclick = () => { t.remove(); onClick(); };
  document.body.append(t);
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.remove(), onClick ? 4000 : 2600);
}
function modal(html, onMount, { locked = false } = {}) {
  const bg = document.createElement('div');
  bg.className = 'modal-bg';
  bg.innerHTML = `<div class="modal">${html}</div>`;
  document.body.append(bg);
  const onKey = e => { if (e.key === 'Escape' && !locked) close(); };
  const close = () => { bg.remove(); document.removeEventListener('keydown', onKey); };
  document.addEventListener('keydown', onKey);
  bg.addEventListener('click', e => {
    if ((!locked && e.target === bg) || e.target.closest('[data-close]')) close();
  });
  onMount?.(bg.firstElementChild, close);
  bg.querySelector('input')?.focus();
  return close;
}
function updateStatus() {
  const n = net.count();
  $('#netDot').classList.toggle('on', n > 0);
  $('#netText').textContent = n ? '已連線' : '連線中…';
  $('#netText').title = net.clients.map(c => `${c._url} ${c.connected ? '✓' : '✗'}`).join('\n');
}
function renderMe() {
  $('#meAv').outerHTML = avatar(S.me.name || '?', S.me.code).replace('class="av ', 'id="meAv" class="av ');
  $('#meName').textContent = S.me.name || '（未設定名稱）';
  $('#meCode').textContent = 'ID ' + fmtCode(S.me.code);
}
const byTs = (a, b) => (b.lastTs || 0) - (a.lastTs || 0);
function itemHtml(c) {
  const isRoom = c.type === 'room';
  const title = isRoom ? c.title : c.name;
  const prev = c.status === 'pending-out' ? '等待對方同意…' : (c.last || (isRoom ? `代號 ${c.roomId}` : fmtCode(c.code)));
  return `<div class="item ${S.active === c.id ? 'active' : ''} ${c.unread ? 'unread' : ''}" data-id="${esc(c.id)}">
    ${avatar(title, c.id, isRoom ? 'room' : '')}
    <div class="mid"><div class="t">${isRoom ? '# ' : ''}${esc(title)}${c.muted ? ' <span title="已關閉通知">🔕</span>' : ''}</div><div class="p">${esc(prev)}</div></div>
    <div class="r"><span>${c.lastTs ? fmtTime(c.lastTs) : ''}</span>${c.unread ? `<span class="badge ${c.muted ? 'muted' : ''}">${badgeNum(c.unread)}</span>` : ''}</div>
  </div>`;
}
function renderList() {
  const all = [...S.convs.values()].filter(c => c.status !== 'declined');
  const reqs = all.filter(c => c.type === 'friend' && c.status === 'pending-in');
  const rooms = all.filter(c => c.type === 'room').sort(byTs);
  const friends = all.filter(c => c.type === 'friend' && c.status !== 'pending-in').sort(byTs);
  let h = '';
  if (!S.settings.ntfDismissed) {
    if ('Notification' in window && Notification.permission === 'default')
      h += `<div class="ntf-bar">🔔<span class="mid">開啟通知，有新訊息時會像 App 一樣提醒你並顯示未讀數</span><button class="btn sm pri" data-ntf-on>開啟</button><button class="icon-btn" data-ntf-x title="不要再提示">×</button></div>`;
    else if (isIOS && !standalone())
      h += `<div class="ntf-bar">📲<span class="mid">iPhone 請按「分享 → 加入主畫面」，從主畫面開啟才能收到通知與圖示未讀數</span><button class="icon-btn" data-ntf-x title="不要再提示">×</button></div>`;
  }
  if (reqs.length) {
    h += `<div class="sec">好友邀請</div>` + reqs.map(c => `<div class="req" data-req="${esc(c.id)}">
      ${avatar(c.name, c.id)}<div class="mid"><div class="t" style="font-weight:600">${esc(c.name)}</div><div class="p" style="font-size:12px;color:var(--muted)">ID ${fmtCode(c.code)}</div></div>
      <button class="btn sm pri" data-acc>接受</button><button class="btn sm" data-dec>拒絕</button></div>`).join('');
  }
  h += `<div class="sec">聊天室</div>` + (rooms.length ? rooms.map(itemHtml).join('') : `<div class="empty">還沒有聊天室，按「＋ 聊天室」建立或加入</div>`);
  h += `<div class="sec">好友</div>` + (friends.length ? friends.map(itemHtml).join('') : `<div class="empty">還沒有好友，按「＋ 好友」輸入對方的 ID 碼</div>`);
  $('#list').innerHTML = h;
  updateBadge();
}
$('#list').addEventListener('click', e => {
  if (e.target.closest('[data-ntf-on]')) return enableNotify();
  if (e.target.closest('[data-ntf-x]')) {
    S.settings.ntfDismissed = true;
    db.put('kv', S.settings, 'settings');
    return renderList();
  }
  const req = e.target.closest('[data-req]');
  if (req) {
    const c = S.convs.get(req.dataset.req);
    if (e.target.closest('[data-acc]')) serial(() => acceptFriend(c));
    else if (e.target.closest('[data-dec]')) serial(() => declineFriend(c));
    return;
  }
  const it = e.target.closest('.item');
  if (it) openConv(it.dataset.id);
});

function openConv(id) {
  const c = S.convs.get(id);
  if (!c) return;
  if (S.active !== id || c.unread) S.unreadMark = { conv: id, n: c.unread || 0 };
  S.active = id;
  if (c.unread) { c.unread = 0; saveConv(c); }
  clearNotifs(id);
  document.body.classList.add('chat-open');
  renderChat();
  renderList();
}
function closeConv() {
  S.active = null;
  S.unreadMark = null;
  document.body.classList.remove('chat-open');
  $('#main').innerHTML = `<div class="welcome"><div style="font-size:48px">💬</div><h2>Cladue 聊天</h2><p>選擇左側的聊天室或好友開始聊天。</p></div>`;
  renderList();
}
function renderHeadSub() {
  const c = S.convs.get(S.active);
  const el = $('#headSub');
  if (!c || !el) return;
  if (c.type === 'room') {
    const on = onlineList(c);
    el.textContent = `代號 ${c.roomId}・線上 ${on.length + 1} 人${on.length ? '：你、' + on.map(x => x.name).join('、') : ''}`;
  } else {
    el.textContent = `ID ${fmtCode(c.code)}${c.status === 'pending-out' ? '・等待對方同意' : ''}`;
  }
}
function renderChat() {
  const c = S.convs.get(S.active);
  if (!c) return closeConv();
  const isRoom = c.type === 'room';
  const title = isRoom ? '# ' + c.title : c.name;
  const canChat = isRoom || c.status === 'friend';
  $('#main').innerHTML = `
    <div class="chat-head">
      <button class="icon-btn back" id="backBtn" title="返回">‹</button>
      ${avatar(isRoom ? c.title : c.name, c.id, 'sm ' + (isRoom ? 'room' : ''))}
      <div class="mid"><div class="t">${esc(title)}</div><div class="s" id="headSub"></div></div>
      ${isRoom ? `<button class="btn sm" id="invBtn">邀請</button>` : ''}
      <button class="icon-btn" id="infoBtn" title="資訊">⋯</button>
    </div>
    <div class="msgs" id="msgs"></div>
    <div class="composer ${canChat ? '' : 'hidden'}">
      <textarea id="input" rows="1" placeholder="輸入訊息…" maxlength="${MAX_LEN}"></textarea>
      <button class="btn pri" id="sendBtn">傳送</button>
    </div>`;
  renderHeadSub();
  $('#backBtn').onclick = closeConv;
  $('#infoBtn').onclick = () => (isRoom ? roomInfo(c) : friendInfo(c));
  if (isRoom) $('#invBtn').onclick = () => openInvite(c);
  const ta = $('#input');
  const send = () => {
    const text = ta.value.trim();
    if (!text) return;
    ta.value = '';
    ta.style.height = '';
    serial(() => (isRoom ? sendRoomMsg(c, text) : sendDm(c, text)));
    ta.focus();
  };
  $('#sendBtn').onclick = send;
  ta.addEventListener('input', () => { ta.style.height = ''; ta.style.height = Math.min(ta.scrollHeight, 140) + 'px'; });
  ta.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey && !e.isComposing && !matchMedia('(pointer:coarse)').matches) { e.preventDefault(); send(); }
  });
  renderMsgs();
}
let lastDay = '';
async function renderMsgs() {
  const c = S.convs.get(S.active);
  const box = $('#msgs');
  if (!c || !box) return;
  const list = (await db.convMsgs(c.id)).slice(-500);
  if (S.active !== c.id) return;
  lastDay = '';
  let h = '';
  if (c.type === 'friend' && c.status === 'pending-out')
    h += `<div class="notice"><div class="big">⏳</div>已送出好友邀請給<br><b>ID ${fmtCode(c.code)}</b><br>對方開啟 App 並同意後即可開始聊天。</div>`;
  if (c.type === 'friend' && c.status === 'pending-in')
    h += `<div class="notice"><div class="big">👋</div><b>${esc(c.name)}</b> 想加你為好友<br><br><button class="btn pri" id="accBtn">接受</button> <button class="btn" id="decBtn">拒絕</button></div>`;
  // 「以下為未讀訊息」分隔線：往回數 n 則別人的訊息
  const mark = S.unreadMark?.conv === c.id ? S.unreadMark : null;
  let cut = -1;
  if (mark?.n) {
    for (let i = list.length - 1, k = 0; i >= 0; i--) {
      if (list[i].from === S.me.code || list[i].sys) continue;
      cut = i;
      if (++k >= mark.n) break;
    }
  }
  h += list.map((m, i) => (i === cut ? `<div class="unread-line" id="unreadLine">以下為未讀訊息</div>` : '') + msgHtml(m)).join('');
  box.innerHTML = h;
  $('#accBtn')?.addEventListener('click', () => serial(() => acceptFriend(c)));
  $('#decBtn')?.addEventListener('click', () => serial(() => declineFriend(c)));
  const line = $('#unreadLine', box);
  if (line && !mark.shown) { mark.shown = true; box.scrollTop = line.offsetTop - box.offsetTop - 60; }
  else box.scrollTop = box.scrollHeight;
}
function dayLabel(ts) {
  const d = new Date(ts);
  const k = d.toDateString();
  if (k === lastDay) return '';
  lastDay = k;
  const w = '日一二三四五六'[d.getDay()];
  return `<div class="day">${d.getFullYear()}/${d.getMonth() + 1}/${d.getDate()}（${w}）</div>`;
}
const linkify = s => esc(s).replace(/https?:\/\/[^\s<]+/g, u => `<a href="${u}" target="_blank" rel="noopener noreferrer">${u}</a>`);
function msgHtml(m) {
  const day = dayLabel(m.ts);
  const time = new Date(m.ts).toTimeString().slice(0, 5);
  if (m.sys) return day + `<div class="sys">${esc(m.name || '')} ${esc(m.text)}・${time}</div>`;
  const mine = m.from === S.me.code;
  if (m.kind === 'inv') {
    return day + `<div class="card" data-mid="${esc(m.id)}"><div class="t">📨 聊天室邀請</div>
      <div class="s">${mine ? '你' : esc(m.name)} 邀請${mine ? '對方' : '你'}加入「${esc(m.title)}」・${time} <span class="st">${stateMark(m)}</span></div>
      ${mine ? '' : `<button class="btn pri sm" data-join="${esc(m.id)}">加入聊天室</button>`}</div>`;
  }
  const c = S.convs.get(m.conv);
  const showName = c?.type === 'room' && !mine;
  return day + `<div class="m ${mine ? 'mine' : ''}" data-mid="${esc(m.id)}">
    ${showName ? `<div class="who">${esc(m.name)} <span style="opacity:.6">${fmtCode(m.from).slice(0, 4)}</span></div>` : ''}
    <div class="row"><div class="bub">${linkify(m.text)}</div><div class="meta">${time} <span class="st">${stateMark(m)}</span></div></div></div>`;
}
function appendMsg(m) {
  const box = $('#msgs');
  if (!box) return;
  const last = box.querySelector('[data-mid]');
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 80;
  // 時間比最後一則早（例如補歷史）就整個重畫
  db.convMsgs(m.conv, m.ts).then(after => {
    if (after.some(x => x.id !== m.id) || !last) return renderMsgs();
    box.insertAdjacentHTML('beforeend', msgHtml(m));
    if (atBottom || m.from === S.me.code) box.scrollTop = box.scrollHeight;
  });
}
$('#main').addEventListener('click', e => {
  const b = e.target.closest('[data-join]');
  if (!b) return;
  db.get('msgs', b.dataset.join).then(m => m && joinRoom(m.roomId, m.pass, m.title));
});

/* ---------- 對話框 ---------- */
const muteRow = c => `<label class="pick" style="margin-top:12px"><input type="checkbox" id="mute" ${c.muted ? 'checked' : ''}> 🔕 關閉這個對話的通知（不計入 App 未讀數）</label>`;
function bindMute(el, c) {
  $('#mute', el).onchange = e => { c.muted = e.target.checked || undefined; saveConv(c); renderList(); };
}
function openNewRoom() {
  const pw = rid(4);
  modal(`<h3>建立 / 加入聊天室</h3>
    <label>聊天室代號</label><input type="text" id="rId" placeholder="例如：team-lunch" autocomplete="off">
    <label>密碼</label><input type="text" id="rPw" value="${pw}" autocomplete="off">
    <label>顯示名稱（選填，只有自己看到）</label><input type="text" id="rT" placeholder="不填就用代號">
    <div class="hint">「代號＋密碼」都相同的人才會進到同一個聊天室。<br>建立新聊天室時用預設的隨機密碼即可；要加入別人的聊天室，請輸入對方給你的代號與密碼。<br>也可以直接用「邀請」功能把連結或 QR Code 傳給對方。</div>
    <div class="acts"><button class="btn" data-close>取消</button><button class="btn pri" id="ok">進入聊天室</button></div>`,
  (el, close) => {
    const go = () => { const id = $('#rId', el).value, pw2 = $('#rPw', el).value; if (!id.trim() || !pw2) return toast('請輸入代號與密碼'); close(); serial(() => joinRoom(id, pw2, $('#rT', el).value)); };
    $('#ok', el).onclick = go;
    el.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  });
}
function openAddFriend(prefill = '') {
  modal(`<h3>加好友</h3>
    <label>對方的 ID 碼</label><input type="text" id="fc" placeholder="XXXX-XXXX-XXXX" value="${esc(fmtCode(normCode(prefill)))}" autocomplete="off" style="font-family:ui-monospace,Consolas,monospace;letter-spacing:.05em">
    <div class="hint">請對方打開 App →點左上角自己的名字，就能看到 ID 碼與 QR Code。<br>用手機相機掃對方的 QR Code 會直接開啟並填好 ID 碼。</div>
    <div class="acts"><button class="btn" data-close>取消</button><button class="btn pri" id="ok">送出邀請</button></div>`,
  (el, close) => {
    const go = () => serial(async () => { if (await addFriend($('#fc', el).value)) close(); });
    $('#ok', el).onclick = go;
    el.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
  });
}
function openInvite(room) {
  const friends = [...S.convs.values()].filter(c => c.type === 'friend' && c.status === 'friend').sort(byTs);
  const link = joinLink(room);
  modal(`<h3>邀請加入「${esc(room.title)}」</h3>
    <div class="tabs"><button class="btn pri" data-tab="f">邀請好友</button><button class="btn" data-tab="l">連結 / QR Code</button></div>
    <div data-pane="f">
      ${friends.length ? friends.map(f => `<label class="pick"><input type="checkbox" value="${esc(f.code)}">${avatar(f.name, f.id, 'sm')}<span>${esc(f.name)}</span></label>`).join('')
        : `<div class="empty" style="padding:8px 0">還沒有好友。可以改用「連結 / QR Code」分享。</div>`}
      <div class="acts"><button class="btn" data-close>關閉</button><button class="btn pri" id="sendInv" ${friends.length ? '' : 'disabled'}>送出邀請</button></div>
    </div>
    <div data-pane="l" class="hidden">
      <div class="qr">${qrSvg(link)}</div>
      <div class="hint" style="text-align:center">用手機相機掃描即可加入。連結內含聊天室密碼，請只傳給信任的人。</div>
      <div class="hint" style="text-align:center">代號 <b>${esc(room.roomId)}</b>・密碼 <b>${esc(room.pass)}</b></div>
      <div class="acts"><button class="btn" data-close>關閉</button><button class="btn" id="cpy">複製連結</button><button class="btn pri" id="shr">分享…</button></div>
    </div>`,
  (el, close) => {
    el.querySelectorAll('[data-tab]').forEach(b => b.onclick = () => {
      el.querySelectorAll('[data-tab]').forEach(x => x.classList.toggle('pri', x === b));
      el.querySelectorAll('[data-pane]').forEach(p => p.classList.toggle('hidden', p.dataset.pane !== b.dataset.tab));
    });
    $('#cpy', el).onclick = () => copy(link);
    $('#shr', el).onclick = () => share(`加入 Cladue 聊天室「${room.title}」`, link);
    $('#sendInv', el).onclick = () => {
      const codes = [...el.querySelectorAll('input[type=checkbox]:checked')].map(x => x.value);
      if (!codes.length) return toast('請勾選好友');
      close();
      serial(async () => { for (const code of codes) await inviteFriend(S.convs.get('f:' + code), room); toast(`已邀請 ${codes.length} 位好友`); });
    };
  });
}
function roomInfo(c) {
  const on = onlineList(c);
  modal(`<h3># ${esc(c.title)}</h3>
    <div class="hint" style="font-size:14px">代號：<b>${esc(c.roomId)}</b><br>密碼：<b>${esc(c.pass)}</b></div>
    <label>線上成員（${on.length + 1}）</label>
    <div>你（${esc(S.me.name)}）${on.map(x => `<br>${esc(x.name)} <span style="color:var(--muted);font-size:12px">ID ${fmtCode(x.code)}</span>`).join('')}</div>
    <label>顯示名稱</label><input type="text" id="rT" value="${esc(c.title)}">
    ${muteRow(c)}
    <div class="hint">訊息只存在每個成員自己的裝置。新成員加入時，若有其他成員在線，會自動補最近 ${SYNC_MAX} 則訊息。</div>
    <div class="acts"><button class="btn danger" id="leave">離開聊天室</button><button class="btn" data-close>關閉</button><button class="btn pri" id="save">儲存</button></div>`,
  (el, close) => {
    bindMute(el, c);
    $('#save', el).onclick = () => { c.title = $('#rT', el).value.trim() || c.roomId; saveConv(c); close(); renderChat(); renderList(); };
    $('#leave', el).onclick = () => { if (confirm('離開後會刪除這個聊天室在本機的所有訊息，確定？')) { close(); serial(() => leaveRoom(c)); } };
  });
}
function friendInfo(c) {
  modal(`<h3>${esc(c.name)}</h3>
    <div class="code-big">${fmtCode(c.code)}</div>
    <div class="hint" style="text-align:center">${c.status === 'friend' ? '好友・私訊以你們兩人的金鑰端對端加密' : c.status === 'pending-out' ? '等待對方同意好友邀請' : ''}</div>
    ${muteRow(c)}
    <div class="acts"><button class="btn danger" id="del">${c.status === 'friend' ? '刪除好友' : '取消邀請'}</button><button class="btn" data-close>關閉</button></div>`,
  (el, close) => {
    bindMute(el, c);
    $('#del', el).onclick = () => { if (confirm('會刪除本機與此好友的所有訊息，確定？')) { close(); serial(() => removeConv(c)); } };
  });
}
function openMe(first = false) {
  const link = addLink();
  modal(`<h3>${first ? '歡迎使用 Cladue 聊天' : '我的資料'}</h3>
    <label>我的名稱</label><input type="text" id="nm" value="${esc(S.me.name)}" maxlength="40" placeholder="朋友會看到這個名稱">
    ${first ? `<div class="hint">這台裝置已自動產生專屬 ID 碼與加密金鑰，資料只存在這台裝置上。</div>
      <div class="acts"><button class="btn pri" id="saveNm">開始使用</button></div>` : `
    <div class="acts" style="margin-top:8px"><button class="btn pri sm" id="saveNm">儲存名稱</button></div>
    <hr>
    <label>我的 ID 碼（這台裝置專屬）</label>
    <div class="code-big">${fmtCode(S.me.code)}</div>
    <div class="qr">${qrSvg(link)}</div>
    <div class="hint" style="text-align:center">對方用手機相機掃描，或輸入 ID 碼，就能送出好友邀請。</div>
    <div class="acts" style="justify-content:center"><button class="btn" id="cpy">複製加好友連結</button><button class="btn pri" id="shr">分享…</button></div>
    <hr>
    <label>通知</label>
    <button class="btn sm" id="ntf">${canNotify() ? '已開啟（App 開著時）' : '開啟訊息通知'}</button>
    <label class="pick" style="margin-top:8px"><input type="checkbox" id="pv" ${S.settings.preview !== false ? 'checked' : ''}> 通知中顯示訊息內容</label>
    <div class="hint">安裝成 App（加入主畫面）後，App 圖示會顯示未讀數字。個別對話可在「⋯」裡關閉通知。<br>本程式沒有雲端主機，App 必須開著（可在背景）才能收到訊息。對方離線時，好友邀請／私訊會在雙方都上線時自動補送（最多保留 7 天）。</div>
    <label>備份 / 換手機</label>
    <div style="display:flex;gap:8px;flex-wrap:wrap"><button class="btn sm" id="exp">匯出備份</button><button class="btn sm" id="imp">匯入備份</button><input type="file" id="impF" accept=".json,application/json" class="hidden"></div>
    <div class="hint">備份檔包含你的 ID 金鑰與所有聊天紀錄，請妥善保管。匯入後會取代這台裝置目前的資料。</div>
    <label>中繼伺服器（一行一個 wss:// 位址，所有人需至少有一台相同）</label>
    <textarea id="brk" rows="3" style="font-family:ui-monospace,Consolas,monospace;font-size:12px">${esc(S.settings.brokers.join('\n'))}</textarea>
    <div class="acts" style="justify-content:space-between"><button class="btn danger sm" id="wipe">清除本機所有資料</button><button class="btn sm" id="saveBrk">套用伺服器設定</button></div>
    <div class="hint" style="text-align:right">v${APP_VER}</div>`}`,
  (el, close) => {
    $('#saveNm', el).onclick = async () => {
      const v = $('#nm', el).value.trim().slice(0, 40);
      if (!v) return toast('請輸入名稱');
      S.me.name = v;
      await db.put('kv', S.me, 'identity');
      renderMe();
      if (first) close(); else toast('已儲存');
    };
    if (first) { $('#nm', el).addEventListener('keydown', e => { if (e.key === 'Enter') $('#saveNm', el).click(); }); return; }
    $('#cpy', el).onclick = () => copy(link);
    $('#shr', el).onclick = () => share(`加我 Cladue 好友（ID ${fmtCode(S.me.code)}）`, link);
    $('#ntf', el).onclick = async e => {
      const p = await enableNotify();
      e.target.textContent = p === 'granted' ? '已開啟（App 開著時）' : p === 'unsupported' ? '此裝置不支援' : '未允許通知';
    };
    $('#pv', el).onchange = e => { S.settings.preview = e.target.checked; db.put('kv', S.settings, 'settings'); };
    $('#exp', el).onclick = exportBackup;
    $('#imp', el).onclick = () => $('#impF', el).click();
    $('#impF', el).onchange = e => e.target.files[0] && importBackup(e.target.files[0]);
    $('#saveBrk', el).onclick = async () => {
      const list = $('#brk', el).value.split(/\s+/).map(s => s.trim()).filter(s => /^wss?:\/\//.test(s));
      S.settings.brokers = list.length ? list : DEFAULT_BROKERS.slice();
      await db.put('kv', S.settings, 'settings');
      net.stop(); net.start();
      toast('已重新連線');
    };
    $('#wipe', el).onclick = async () => {
      if (!confirm('會永久刪除這台裝置上的 ID 碼、好友與所有訊息（建議先匯出備份），確定？')) return;
      net.stop();
      await db.clearAll();
      location.reload();
    };
  }, { locked: first });
}
async function exportBackup() {
  const data = { app: 'cladue', ver: 1, at: now(), identity: S.me, settings: S.settings, convs: await db.all('convs'), msgs: await db.all('msgs'), outbox: await db.all('outbox') };
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([JSON.stringify(data)], { type: 'application/json' }));
  a.download = `cladue-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}
async function importBackup(file) {
  let d;
  try { d = JSON.parse(await file.text()); } catch { return toast('檔案格式錯誤'); }
  if (d?.app !== 'cladue' || !d.identity?.privJwk) return toast('不是 Cladue 備份檔');
  if (!confirm('匯入會取代這台裝置目前的所有資料，確定？')) return;
  net.stop();
  await db.clearAll();
  await db.put('kv', d.identity, 'identity');
  if (d.settings) await db.put('kv', d.settings, 'settings');
  for (const c of d.convs || []) await db.put('convs', c);
  for (const m of d.msgs || []) await db.put('msgs', m);
  for (const o of d.outbox || []) await db.put('outbox', o);
  location.reload();
}

/* ---------- 啟動 ---------- */
$('#meBtn').onclick = () => openMe();
$('#newRoomBtn').onclick = openNewRoom;
$('#addFriendBtn').onclick = () => openAddFriend();
window.addEventListener('hashchange', handleHash);
document.addEventListener('visibilitychange', markActiveRead);
window.addEventListener('focus', markActiveRead);
// 點系統通知 → service worker 通知這個頁面開啟對應對話
navigator.serviceWorker?.addEventListener('message', e => {
  if (e.data?.type === 'open' && typeof e.data.conv === 'string') openConv(e.data.conv);
});
window.addEventListener('pagehide', () => {
  for (const c of S.convs.values()) if (c.type === 'room' && S.roomKeys.has(c.id))
    enc(S.roomKeys.get(c.id), { k: 'bye', from: S.me.code }).then(e => net.pub(c.topic, { v: 1, ...e }));
});

async function main() {
  if (!window.isSecureContext || !crypto.subtle) {
    $('#main').innerHTML = `<div class="welcome"><h2>需要 HTTPS</h2><p>請用 https:// 網址（例如 GitHub Pages）開啟本頁。</p></div>`;
    return;
  }
  await db.open();
  await initIdentity();
  S.settings = (await db.get('kv', 'settings')) || { brokers: DEFAULT_BROKERS.slice() };
  for (const c of await db.all('convs')) S.convs.set(c.id, c);
  for (const k of await db.keys('msgs')) S.msgIds.add(k);
  renderMe();
  renderList();
  net.start();
  if (!S.me.name) openMe(true);
  handleHash();

  setInterval(() => serial(flushOutbox), RESEND_MS);
  setInterval(() => serial(async () => {
    if (!net.count()) return;
    for (const c of S.convs.values()) {
      if (c.type !== 'room') continue;
      net.pub(c.topic, { v: 1, ...(await enc(await roomKey(c), { k: 'ping', from: S.me.code, name: S.me.name })) });
      c.aliveTs = now();
      await db.put('convs', c);
    }
    if (S.active) renderHeadSub();
  }), PING_MS);

  if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
}
main().catch(e => { console.error(e); toast('啟動失敗：' + e.message); });
})();
