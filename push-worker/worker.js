/* Cladue 推播伺服器（Cloudflare Worker + KV，免費方案即可）
 * 只保存「推播訂閱」與「頻道雜湊 → 訂閱」的對應，不經手明文：
 * 訊息在送進來之前就已經用聊天室 / 好友金鑰端對端加密，這裡只是再包一層 Web Push 加密轉給 Apple / Google / Microsoft。
 * 綁定：KV namespace，變數名稱 SUBS
 * API：
 *   GET  /vapid     → { key }               VAPID 公鑰（第一次呼叫時自動產生並存在 KV）
 *   POST /register  { sub, topics }          登記這台裝置要收哪些頻道的推播
 *   POST /push      { topic, except, data }  推播給訂閱該頻道的所有裝置（except = 發送者自己的訂閱 id）
 */
const SUBJECT = 'https://chrisleimeng.github.io/cladue-chat/';  // VAPID 聯絡資訊（Apple 要求是 https 或 mailto）
const SUB_TTL = 90 * 86400;     // 訂閱 90 天沒更新就自動過期
const MAX_DATA = 3200;          // Web Push 內容上限約 4KB
const MAX_TARGETS = 40;         // 免費方案每次請求最多 50 個對外連線
const TOPIC_RE = /^cladue\/v1\/[ur]\/[A-Za-z0-9]{12,64}$/;
const CORS = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type' };

const te = new TextEncoder();
const b64u = u8 => { let s = ''; for (const b of u8) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, '0')).join('');
const subId = async endpoint => hex(new Uint8Array(await crypto.subtle.digest('SHA-256', te.encode(endpoint)))).slice(0, 32);

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });
    const json = (o, status = 200) => new Response(JSON.stringify(o), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
    const { pathname } = new URL(req.url);
    try {
      if (!env.SUBS) throw new Error('尚未綁定 KV（變數名稱必須是 SUBS）');
      if (pathname === '/vapid') return json({ key: (await vapid(env)).pub });
      if (req.method === 'POST' && pathname === '/register') return json(await register(env, await req.json()));
      if (req.method === 'POST' && pathname === '/push') return json(await push(env, await req.json()));
      return json({ app: 'cladue-push', ok: true });
    } catch (e) {
      return json({ error: String(e?.message || e) }, 400);
    }
  },
};

/* ---------- VAPID 金鑰（自動產生一次，存在 KV） ---------- */
let VAPID = null;
async function vapid(env) {
  if (VAPID) return VAPID;
  let v = await env.SUBS.get('vapid', 'json');
  if (!v) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    v = { jwk: await crypto.subtle.exportKey('jwk', kp.privateKey), pub: b64u(new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey))) };
    await env.SUBS.put('vapid', JSON.stringify(v));
  }
  VAPID = { pub: v.pub, key: await crypto.subtle.importKey('jwk', v.jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']) };
  return VAPID;
}

/* ---------- 訂閱 ---------- */
// KV 結構：s:<id> → 訂閱、e:<id> → 該裝置的頻道清單、t:<topic> → 訂閱 id 清單
async function register(env, b) {
  const sub = b?.sub;
  if (!sub || typeof sub.endpoint !== 'string' || !/^https:\/\//.test(sub.endpoint) || typeof sub.keys?.p256dh !== 'string' || typeof sub.keys?.auth !== 'string')
    throw new Error('bad subscription');
  const topics = [...new Set(Array.isArray(b.topics) ? b.topics : [])].filter(t => typeof t === 'string' && TOPIC_RE.test(t)).slice(0, 300);
  const id = await subId(sub.endpoint);
  const old = (await env.SUBS.get('e:' + id, 'json')) || [];
  await env.SUBS.put('s:' + id, JSON.stringify({ endpoint: sub.endpoint, keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth } }), { expirationTtl: SUB_TTL });
  await env.SUBS.put('e:' + id, JSON.stringify(topics), { expirationTtl: SUB_TTL });
  for (const t of old) if (!topics.includes(t)) await editTopic(env, t, ids => ids.filter(x => x !== id));
  for (const t of topics) await editTopic(env, t, ids => (ids.includes(id) ? ids : [...ids, id]));
  return { id, topics: topics.length };
}
async function editTopic(env, topic, fn) {
  const k = 't:' + topic;
  const before = (await env.SUBS.get(k, 'json')) || [];
  const after = fn(before);
  if (after.length === before.length) return;  // 沒變就不寫，省 KV 寫入額度
  if (after.length) await env.SUBS.put(k, JSON.stringify(after)); else await env.SUBS.delete(k);
}

/* ---------- 推播 ---------- */
async function push(env, b) {
  const topic = b?.topic;
  if (typeof topic !== 'string' || !TOPIC_RE.test(topic)) throw new Error('bad topic');
  const payload = JSON.stringify(b.data ?? {});
  if (payload.length > MAX_DATA) throw new Error('payload too large');
  const ids = ((await env.SUBS.get('t:' + topic, 'json')) || []).filter(id => id !== b.except).slice(0, MAX_TARGETS);
  if (!ids.length) return { sent: 0 };
  const v = await vapid(env);
  const gone = [];
  const ok = await Promise.all(ids.map(async id => {
    const sub = await env.SUBS.get('s:' + id, 'json');
    if (!sub) { gone.push(id); return 0; }
    try {
      const r = await sendPush(v, sub, payload);
      if (r.status === 404 || r.status === 410) { gone.push(id); await env.SUBS.delete('s:' + id); }
      return r.ok ? 1 : 0;
    } catch { return 0; }
  }));
  if (gone.length) await editTopic(env, topic, x => x.filter(id => !gone.includes(id)));
  return { sent: ok.reduce((a, x) => a + x, 0) };
}
async function sendPush(v, sub, payload) {
  const jwt = await signJwt(v.key, { aud: new URL(sub.endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: SUBJECT });
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: { Authorization: `vapid t=${jwt}, k=${v.pub}`, 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '86400', Urgency: 'high' },
    body: await encrypt(sub, te.encode(payload)),
  });
}
async function signJwt(key, claims) {
  const data = b64u(te.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' }))) + '.' + b64u(te.encode(JSON.stringify(claims)));
  return data + '.' + b64u(new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, te.encode(data))));
}

/* ---------- Web Push 內容加密（RFC 8291, aes128gcm） ---------- */
async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
export async function encrypt(sub, plain, fixed = {}) {
  const ECDH = { name: 'ECDH', namedCurve: 'P-256' };
  const uaPub = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const kp = fixed.kp || await crypto.subtle.generateKey(ECDH, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', kp.publicKey));
  const ua = await crypto.subtle.importKey('raw', uaPub, ECDH, false, []);
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: ua }, kp.privateKey, 256));
  const ikm = await hkdf(auth, shared, concat(te.encode('WebPush: info\0'), uaPub, asPub), 32);
  const salt = fixed.salt || crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, te.encode('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, te.encode('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, concat(plain, new Uint8Array([2]))));
  const head = new Uint8Array(21);
  head.set(salt);
  new DataView(head.buffer).setUint32(16, 4096);
  head[20] = asPub.length;
  return concat(head, asPub, ct);
}
