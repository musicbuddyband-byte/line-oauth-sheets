import 'dotenv/config';
import express from 'express';
import cookieSession from 'cookie-session';
import axios from 'axios';
import qs from 'qs';
import crypto from 'crypto';
import { google } from 'googleapis';
import path from 'node:path';
import fs from 'node:fs';
import ngrok from 'ngrok';

/* ---------- Pretty boot info ---------- */
function printStartupInfo({ baseUrl, port, bots }) {
  const box = (s) => `\n${'='.repeat(64)}\n${s}\n${'='.repeat(64)}\n`;
  const lines = [
    `✅ Server is ready`,
    `• Local Dev URL        : http://localhost:${port}`,
    `• Public BASE_URL      : ${baseUrl || '(not set)'}`,
    `• LINE Callback URL    : ${baseUrl ? baseUrl + '/callback/:bot' : '(set BASE_URL first)'}`,
    `• Google Sheet ID      : ${process.env.SHEET_ID}`,
    `• Sheet Name           : ${process.env.SHEET_NAME || 'Users'}`,
    `• Active Bots          : ${bots.join(', ') || '(none)'}`,
    `• NODE_ENV             : ${process.env.NODE_ENV || '(not set)'}`
  ];
  console.log(box(lines.join('\n')));
}

/* ---------- ENV ---------- */
const {
  SHEET_ID, SHEET_NAME = 'Users',
  GOOGLE_APPLICATION_CREDENTIALS,
  BOTS = ''
} = process.env;

if (!SHEET_ID) {
  console.error('กรุณากรอก .env ให้ครบ (SHEET_ID)');
  process.exit(1);
}
if (!GOOGLE_APPLICATION_CREDENTIALS || !fs.existsSync(GOOGLE_APPLICATION_CREDENTIALS)) {
  console.error('ไม่พบไฟล์ Service Account:', GOOGLE_APPLICATION_CREDENTIALS);
  process.exit(1);
}

const BOT_LIST = BOTS.split(',').map(s => s.trim()).filter(Boolean);
if (BOT_LIST.length === 0) {
  console.warn('⚠️ ยังไม่ได้กำหนด BOTS=OA1,OA2,... ใน .env — ระบบยังทำงานได้ แต่ /login/:bot จะตรวจ bot ไม่ผ่าน');
}

/* ---------- Bot Config Helpers ---------- */
function getBotConfig(botName) {
  if (!botName) return null;
  const key = botName.toUpperCase();
  const id = process.env[`${key}_CHANNEL_ID`];
  const secret = process.env[`${key}_CHANNEL_SECRET`];
  if (!id || !secret) return null;
  return { botName, channelId: id, channelSecret: secret };
}

/* ---------- Google Sheets Client ---------- */
const auth = new google.auth.GoogleAuth({
  keyFile: GOOGLE_APPLICATION_CREDENTIALS,
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});
const sheets = google.sheets({ version: 'v4', auth });

/* ---------- App ---------- */
const app = express();
app.set('trust proxy', 1);
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-me';

app.use(cookieSession({
  name: 'sess',
  secret: COOKIE_SECRET,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
}));

/* ---------- Pages ---------- */
app.get('/', (_, res) => {
  res.sendFile(path.join(process.cwd(), 'views', 'index.html'));
});
app.get('/users', (_, res) => {
  res.sendFile(path.join(process.cwd(), 'views', 'users.html'));
});

/* ---------- Helpers (PKCE) ---------- */
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const createPkce = () => {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
};

/* ---------- Ensure Header ---------- */
async function ensureUsersHeader() {
  // สร้างหัวตารางถ้ายังไม่มี (A1:K1)
  const header = [
    'timestamp', 'userId', 'displayName', 'email', 'pictureUrl',
    'bot_name', 'channel_id', 'first_seen_at', 'last_seen_at', 'status', 'raw_profile_json'
  ];
  try {
    const meta = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `${SHEET_NAME}!A1:K1`,
    });
    const have = Array.isArray(meta.data.values) && meta.data.values.length > 0;
    if (!have) {
      await sheets.spreadsheets.values.update({
        spreadsheetId: SHEET_ID,
        range: `${SHEET_NAME}!A1:K1`,
        valueInputOption: 'RAW',
        requestBody: { values: [header] }
      });
    }
  } catch {
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range: `${SHEET_NAME}!A1:K1`,
      valueInputOption: 'RAW',
      requestBody: { values: [header] }
    });
  }
}

/* ---------- Upsert by (bot_name, userId) ---------- */
async function upsertUserRow({ botName, channelId, user }) {
  await ensureUsersHeader();

  const now = new Date().toISOString();
  const rowValues = [
    now,                      // timestamp
    user.sub || '',           // userId
    user.name || '',          // displayName
    user.email || '',         // email
    user.picture || '',       // pictureUrl
    botName,                  // bot_name
    channelId,                // channel_id
    now,                      // first_seen_at (จะเซ็ตใหม่เฉพาะตอน insert)
    now,                      // last_seen_at
    'login',                  // status
    JSON.stringify(user)      // raw_profile_json
  ];

  // อ่านข้อมูลทั้งหมดเพื่อตรวจหาแถวเดิม (ถ้าข้อมูลใหญ่ ค่อยปรับเป็น batch/valueRenderOptions)
  let existingRow = -1;
  try {
    const all = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `${SHEET_NAME}!A2:K`,
    });
    const rows = all.data.values || [];
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      const rUserId = (r[1] || '');
      const rBot = (r[5] || '');
      if (rUserId === user.sub && rBot === botName) {
        existingRow = i + 2; // offset (A1 header)
        break;
      }
    }
  } catch { /* ignore */ }

  if (existingRow > 0) {
    // อัปเดตเฉพาะคอลัมน์ที่เปลี่ยน + last_seen_at + status + raw_profile_json
    // timestamp และ first_seen_at คงค่าเดิม
    const range = `${SHEET_NAME}!A${existingRow}:K${existingRow}`;
    // ดึงแถวเดิมมาเพื่อคงค่า first_seen_at เดิม (คอลัมน์ H หรือ index 7)
    let oldRow = [];
    try {
      const one = await sheets.spreadsheets.values.get({
        spreadsheetId: SHEET_ID,
        range
      });
      oldRow = one.data.values?.[0] || [];
    } catch { /* ignore */ }

    const firstSeen = oldRow[7] || rowValues[7]; // H
    const merged = [
      oldRow[0] || rowValues[0],    // timestamp (คงของเดิมถ้ามี)
      rowValues[1],                 // userId
      rowValues[2],                 // displayName
      rowValues[3],                 // email
      rowValues[4],                 // pictureUrl
      rowValues[5],                 // bot_name
      rowValues[6],                 // channel_id
      firstSeen,                    // first_seen_at (คงเดิม)
      rowValues[8],                 // last_seen_at (now)
      rowValues[9],                 // status
      rowValues[10]                 // raw_profile_json
    ];

    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID,
      range,
      valueInputOption: 'RAW',
      requestBody: { values: [merged] }
    });
  } else {
    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID,
      range: `${SHEET_NAME}!A:K`,
      valueInputOption: 'RAW',
      requestBody: { values: [rowValues] }
    });
  }
}

/* ---------- STEP 1: /login/:bot ---------- */
app.get('/login/:bot', (req, res) => {
  const botName = String(req.params.bot || '').trim();
  const cfg = getBotConfig(botName);
  if (!cfg) return res.status(400).send(`Unknown bot: ${botName}. โปรดตั้งค่า ${botName}_CHANNEL_ID/SECRET ใน .env`);

  const state = crypto.randomUUID();
  const { verifier, challenge } = createPkce();

  req.session[`state_${botName}`] = state;
  req.session[`verifier_${botName}`] = verifier;

  const url = 'https://access.line.me/oauth2/v2.1/authorize?' + qs.stringify({
    response_type: 'code',
    client_id: cfg.channelId,
    redirect_uri: `${globalThis.BASE_URL}/callback/${encodeURIComponent(botName)}`,
    scope: 'openid profile email',
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    prompt: 'consent'
  });

  res.redirect(url);
});

/* ---------- STEP 2: /callback/:bot → Token → Verify → Upsert ---------- */
app.get('/callback/:bot', async (req, res) => {
  const botName = String(req.params.bot || '').trim();
  const cfg = getBotConfig(botName);
  if (!cfg) return res.status(400).send(`Unknown bot: ${botName}`);

  try {
    const { code, state, error, error_description } = req.query;
    if (error) return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
    if (!code || state !== req.session[`state_${botName}`]) return res.status(400).send('Invalid state/code');

    // 1) Exchange token
    const tokenResp = await axios.post(
      'https://api.line.me/oauth2/v2.1/token',
      qs.stringify({
        grant_type: 'authorization_code',
        code,
        redirect_uri: `${globalThis.BASE_URL}/callback/${encodeURIComponent(botName)}`,
        client_id: cfg.channelId,
        client_secret: cfg.channelSecret,
        code_verifier: req.session[`verifier_${botName}`]
      }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const { id_token } = tokenResp.data;

    // 2) Verify id_token
    const verifyResp = await axios.post(
      'https://api.line.me/oauth2/v2.1/verify',
      qs.stringify({ id_token, client_id: cfg.channelId }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const user = verifyResp.data; // { sub, name, email, picture, ... }

    // 3) Upsert Google Sheet (key = bot_name + userId)
    await upsertUserRow({ botName, channelId: cfg.channelId, user });

    // 4) Pretty page
    const payload = {
      bot: botName,
      channelId: cfg.channelId,
      userId: user.sub || '',
      name: user.name || '',
      email: user.email || '',
      picture: user.picture || ''
    };

    res
      .status(200)
      .set('Content-Type', 'text/html; charset=utf-8')
      .send(`<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width,initial-scale=1" />
<title>บันทึกสำเร็จ • LINE OAuth</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap" rel="stylesheet">
<style>
  :root{
    --bg:#0b1020; --panel:#121a2e; --panel-2:#0f1630; --text:#e8efff; --muted:#9bb0d6;
    --accent:#6ee7ff; --ok:#22c55e; --ring: rgba(110,231,255,.3); --radius:16px;
  }
  *{box-sizing:border-box} html,body{height:100%}
  body{
    margin:0;background:
      radial-gradient(1000px 600px at 10% -10%, rgba(110,231,255,.10), transparent 50%),
      radial-gradient(1000px 700px at 110% 30%, rgba(99,102,241,.12), transparent 45%),
      linear-gradient(180deg, #0b1020 0%, #0a0f22 100%);
    color:var(--text);font:16px/1.6 Poppins, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    display:grid; place-items:center; padding:24px;
  }
  .wrap{max-width:960px; width:100%}
  .card{background:linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
    border:1px solid rgba(255,255,255,.08); border-radius:var(--radius); padding:28px;}
  .hero{display:flex; gap:20px; align-items:center; padding-bottom:12px; border-bottom:1px dashed rgba(255,255,255,.12); margin-bottom:18px;}
  .badge{display:inline-flex; gap:8px; align-items:center;background:rgba(34,197,94,.12); color:#86efac; border:1px solid rgba(34,197,94,.25);
    padding:6px 10px; border-radius:999px; font-weight:600; font-size:12px; letter-spacing:.3px; text-transform:uppercase;}
  .title{font-size:22px; font-weight:700; margin:0}
  .muted{color:var(--muted); font-size:14px}
  .user{display:flex; gap:16px; align-items:center; margin:12px 0 6px}
  .avatar{width:56px; height:56px; border-radius:50%; object-fit:cover; flex:0 0 auto; border:2px solid rgba(255,255,255,.12);}
  .kv{display:grid; gap:8px; margin:12px 0 6px}
  .row{display:flex; gap:8px; align-items:baseline}
  .key{width:110px; color:var(--muted)} .val{font-weight:600; color:var(--text); word-break:break-all}
  .actions{display:flex; flex-wrap:wrap; gap:10px; margin-top:18px}
  .btn{appearance:none; border:1px solid rgba(255,255,255,.12); background:#101935; color:var(--text); padding:10px 14px; border-radius:12px; font-weight:600; letter-spacing:.2px; cursor:pointer;}
  .btn.primary{background:linear-gradient(135deg, #3b82f6 0%, #22d3ee 100%); border-color:transparent}
  .note{font-size:12px; color:var(--muted); margin-top:10px}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <span class="badge">✓ ${payload.bot}</span>
        <h1 class="title">เข้าสู่ระบบด้วย LINE สำเร็จ</h1>
      </div>
      <section class="user">
        <img class="avatar" src="${payload.picture || 'https://i.imgur.com/8Km9tLL.png'}" alt="avatar"/>
        <div>
          <div style="font-size:18px; font-weight:700">${payload.name || '—'}</div>
          <div class="muted">${payload.email || '—'}</div>
        </div>
      </section>

      <div class="kv">
        <div class="row"><div class="key">Bot</div><div class="val">${payload.bot}</div></div>
        <div class="row"><div class="key">Channel ID</div><div class="val">${payload.channelId}</div></div>
        <div class="row"><div class="key">User ID</div><div class="val">${payload.userId}</div></div>
      </div>

      <div class="actions">
        <a class="btn primary" href="https://www.appsheet.com/newshortcut/9484f535-e9ef-49b4-994e-97ba449c3227" target="_blank">📲 ติดตั้ง AppSheet</a>
      </div>
      <p class="note">ปุ่ม “X มุมขวา ด้านบน” จะปิดหน้าต่าง กลับไปยังแชทไลน์</p>
    </div>
  </div>
</body>
</html>`);
  } catch (err) {
    console.error('[DEBUG] callback error:', err?.response?.status, err?.response?.data || err);
    res.status(500).send('Internal error: ' + (err?.response?.data ? JSON.stringify(err.response.data) : String(err)));
  }
});

/* ---------- API: get users JSON ---------- */
app.get('/api/users', async (_, res) => {
  try {
    const { data } = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID,
      range: `${SHEET_NAME}!A1:K`
    });
    const rows = data.values || [];
    const header = rows[0] || [
      'timestamp', 'userId', 'displayName', 'email', 'pictureUrl',
      'bot_name', 'channel_id', 'first_seen_at', 'last_seen_at', 'status', 'raw_profile_json'
    ];
    const items = rows.slice(1).map(r => ({
      timestamp: r[0] || '',
      userId: r[1] || '',
      displayName: r[2] || '',
      email: r[3] || '',
      pictureUrl: r[4] || '',
      bot_name: r[5] || '',
      channel_id: r[6] || '',
      first_seen_at: r[7] || '',
      last_seen_at: r[8] || '',
      status: r[9] || '',
      raw_profile_json: r[10] || ''
    }));
    res.json({ header, items });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

/* ---------- Start ---------- */
const port = process.env.PORT || 3000;
app.listen(port, async () => {
  if (process.env.NODE_ENV === 'development') {
    const url = await ngrok.connect({ addr: port, authtoken: process.env.NGROK_AUTHTOKEN });
    globalThis.BASE_URL = url;
    printStartupInfo({ baseUrl: globalThis.BASE_URL, port, bots: BOT_LIST });
  } else {
    globalThis.BASE_URL = process.env.BASE_URL;
    printStartupInfo({ baseUrl: globalThis.BASE_URL, port, bots: BOT_LIST });
  }
});
