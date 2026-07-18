/* ══════════════════════════════════════════════════════════
   bytenode-account — bytenode 통합 계정 SSO / OAuth 2.0 서버
   계정 원본(DB)은 bytenode109가 소유하며, 이 서버는
   로그인/가입 UI 호스팅 + API 프록시 + OAuth 코드 발급을 담당.
   상태 없는(stateless) 설계라 Vercel 서버리스에서 그대로 동작.
   ══════════════════════════════════════════════════════════ */
const express = require('express');
const jwt     = require('jsonwebtoken');
const path    = require('path');

const app  = express();
const PUB  = path.join(__dirname, 'public');
const PORT = process.env.PORT || 5170;

const BN_API = process.env.BN_API || 'https://bytenode109.vercel.app';

/* OAuth 인가 코드 서명용 시크릿 (bytenode JWT_SECRET과 별개) */
const SSO_SECRET = process.env.SSO_SECRET || 'dev-only-secret-change-me';
if (SSO_SECRET === 'dev-only-secret-change-me') console.warn('⚠ SSO_SECRET 미설정 — 개발용 시크릿 사용 중');

/* ── 등록된 클라이언트(서비스)와 허용 redirect origin ── */
const CLIENTS = {
  bytenode: { origins: ['https://bytenode109.vercel.app'] },
  byteexam: { origins: ['https://byteexam109.vercel.app'] },
  bytetext: { origins: ['https://bytetext.vercel.app'] },
  bytewrite:{ origins: [] } /* 배포 후 EXTRA_ORIGINS로 추가 */
};
/* 환경변수로 origin 추가: EXTRA_ORIGINS=client_id|https://a.com,client_id|https://b.com */
(process.env.EXTRA_ORIGINS || '').split(',').filter(Boolean).forEach(pair => {
  const [cid, origin] = pair.split('|');
  if (CLIENTS[cid] && origin) CLIENTS[cid].origins.push(origin.trim());
});
const DEV_OK = origin => /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);

/* 동적 등록 클라이언트(bn_...)는 bytenode Firestore에서 조회 */
async function getClient(clientId) {
  if (CLIENTS[clientId]) return { clientId, name: clientId, origins: CLIENTS[clientId].origins, builtin: true };
  if (!/^bn_[0-9a-f]{16}$/.test(clientId || '')) return null;
  try {
    const { status, data } = await bn('/api/oauth/clients/' + clientId + '/public');
    return status === 200 ? { ...data, builtin: false } : null;
  } catch { return null; }
}

async function redirectAllowed(clientId, redirectUri) {
  try {
    const u = new URL(redirectUri);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    if (DEV_OK(u.origin)) return true;
    const c = await getClient(clientId);
    return !!c && c.origins.includes(u.origin);
  } catch { return false; }
}

app.use(express.json({ limit: '100kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  /* 각 서비스 프론트에서 직접 호출할 수 있게 CORS 개방 (토큰은 헤더/바디로만 전달) */
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});
app.use(express.static(PUB, { extensions: ['html'] }));

/* ── bytenode API 프록시 ── */
async function bn(endpoint, options = {}) {
  const r = await fetch(BN_API + endpoint, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    signal: AbortSignal.timeout(10_000)
  });
  const data = await r.json().catch(() => ({}));
  return { status: r.status, data };
}

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const { status, data } = await bn('/api/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

app.post('/api/register', async (req, res) => {
  try {
    const { username, displayName, password } = req.body || {};
    const { status, data } = await bn('/api/auth/register', { method: 'POST', body: JSON.stringify({ username, displayName, password }) });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

app.patch('/api/me', async (req, res) => {
  try {
    const { displayName, bio } = req.body || {};
    const { status, data } = await bn('/api/auth/me', {
      method: 'PATCH',
      headers: { Authorization: req.headers.authorization || '' },
      body: JSON.stringify({ displayName, bio })
    });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

app.get('/api/me', async (req, res) => {
  try {
    const authz = req.headers.authorization || '';
    const { status, data } = await bn('/api/auth/me', { headers: { Authorization: authz } });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

/* ── OAuth 2.0 (authorization code) ──
   GET  /authorize?response_type=code&client_id=...&redirect_uri=...&state=...
        → 로그인 UI 표시, 로그인 후 redirect_uri?code=...&state=... 로 이동
   POST /token { grant_type:'authorization_code', code, client_id }
        → { access_token, token_type, user }                              */

app.get('/authorize', (req, res) => res.sendFile(path.join(PUB, 'index.html')));

/* 로그인된 사용자의 bn_token → 인가 코드 발급 */
app.post('/api/authorize', async (req, res) => {
  try {
    const { token, client_id, redirect_uri, state } = req.body || {};
    if (!token || !client_id || !redirect_uri) return res.status(400).json({ error: '필수 파라미터가 없습니다.' });
    if (!(await redirectAllowed(client_id, redirect_uri))) return res.status(400).json({ error: '허용되지 않은 redirect_uri입니다. /developer에서 앱의 redirect origin을 확인하세요.' });

    /* 토큰 유효성은 bytenode에 물어봄 */
    const { status } = await bn('/api/auth/me', { headers: { Authorization: 'Bearer ' + token } });
    if (status !== 200) return res.status(401).json({ error: '세션이 만료되었습니다. 다시 로그인하세요.' });

    const code = jwt.sign({ t: token, ru: redirect_uri }, SSO_SECRET, { audience: client_id, expiresIn: '2m' });
    const u = new URL(redirect_uri);
    u.searchParams.set('code', code);
    if (state) u.searchParams.set('state', state);
    res.json({ location: u.href });
  } catch (e) { res.status(500).json({ error: '서버 오류가 발생했습니다.' }); }
});

app.post('/token', async (req, res) => {
  try {
    const { grant_type, code, client_id, client_secret } = req.body || {};
    if (grant_type && grant_type !== 'authorization_code') return res.status(400).json({ error: 'unsupported_grant_type' });
    if (!code || !client_id) return res.status(400).json({ error: 'invalid_request' });
    /* 개발자 콘솔에서 발급된 앱은 client_secret 필수 */
    if (/^bn_[0-9a-f]{16}$/.test(client_id)) {
      if (!client_secret) return res.status(401).json({ error: 'invalid_client', error_description: 'client_secret이 필요합니다.' });
      const { status } = await bn('/api/oauth/verify', { method: 'POST', body: JSON.stringify({ clientId: client_id, clientSecret: client_secret }) });
      if (status !== 200) return res.status(401).json({ error: 'invalid_client' });
    }
    let payload;
    try { payload = jwt.verify(code, SSO_SECRET, { audience: client_id }); }
    catch { return res.status(400).json({ error: 'invalid_grant' }); }

    const { status, data: user } = await bn('/api/auth/me', { headers: { Authorization: 'Bearer ' + payload.t } });
    if (status !== 200) return res.status(400).json({ error: 'invalid_grant' });
    res.json({ access_token: payload.t, token_type: 'Bearer', user });
  } catch (e) { res.status(500).json({ error: 'server_error' }); }
});

/* OIDC 스타일 userinfo */
app.get('/userinfo', async (req, res) => {
  try {
    const { status, data } = await bn('/api/auth/me', { headers: { Authorization: req.headers.authorization || '' } });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

/* 등록된 클라이언트 목록 (개발자 페이지용) */
app.get('/api/clients', (req, res) => {
  res.json(Object.entries(CLIENTS).map(([id, c]) => ({ client_id: id, origins: c.origins })));
});

/* ── 개발자 콘솔: 내 OAuth 앱 관리 (bytenode 로그인 필요, 프록시) ── */
app.get('/api/apps', async (req, res) => {
  try {
    const { status, data } = await bn('/api/oauth/clients', { headers: { Authorization: req.headers.authorization || '' } });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});
app.post('/api/apps', async (req, res) => {
  try {
    const { status, data } = await bn('/api/oauth/clients', {
      method: 'POST',
      headers: { Authorization: req.headers.authorization || '' },
      body: JSON.stringify({ name: req.body?.name, origins: req.body?.origins })
    });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});
app.delete('/api/apps/:id', async (req, res) => {
  try {
    const { status, data } = await bn('/api/oauth/clients/' + encodeURIComponent(req.params.id), {
      method: 'DELETE',
      headers: { Authorization: req.headers.authorization || '' }
    });
    res.status(status).json(data);
  } catch (e) { res.status(502).json({ error: '계정 서버에 연결할 수 없습니다.' }); }
});

/* 인가 화면에서 앱 이름 표시용 */
app.get('/api/clientinfo/:id', async (req, res) => {
  const c = await getClient(req.params.id);
  if (!c) return res.status(404).json({ error: '등록되지 않은 client_id입니다.' });
  res.json({ clientId: c.clientId, name: c.name });
});

/* 페이지 라우트 */
app.get('/login',     (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.get('/welcome',   (req, res) => res.sendFile(path.join(PUB, 'index.html')));
app.get('/developer', (req, res) => res.sendFile(path.join(PUB, 'developer.html')));

/* 법률 문서 */
app.get('/terms',   (req, res) => res.sendFile(path.join(PUB, 'terms.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(PUB, 'privacy.html')));

app.get('*', (req, res) => res.sendFile(path.join(PUB, 'index.html')));

app.listen(PORT, () => console.log(`\n✅ bytenode-account 실행 중 → http://localhost:${PORT}\n`));

module.exports = app;
