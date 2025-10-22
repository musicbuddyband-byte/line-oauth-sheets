import 'dotenv/config';
import express from 'express';
import cookieSession from 'cookie-session';
import axios from 'axios';
import qs from 'qs';
import crypto from 'crypto';
import { google } from 'googleapis';
import path from 'node:path';
import fs from 'node:fs';

// lazy import ngrok เฉพาะตอน dev
let ngrok;

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
    `• NODE_ENV             : ${process.env.NODE_ENV || '(not set)'}`,
  ];
  console.log(box(lines.join('\n')));
}

/* ---------- ENV ---------- */
const {
  SHEET_ID,
  SHEET_NAME = 'Users',
  GOOGLE_APPLICATION_CREDENTIALS,
  GOOGLE_APPLICATION_CREDENTIALS_JSON,
  BOTS = ''
} = process.env;

if (!SHEET_ID) {
  console.error('❌ กรุณากรอก SHEET_ID ใน .env');
  process.exit(1);
}

// ตรวจสอบ credentials: รองรับทั้ง path และ JSON string
let credentials;
if (GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(GOOGLE_APPLICATION_CREDENTIALS)) {
  credentials = GOOGLE_APPLICATION_CREDENTIALS; // path ไฟล์ service-account.json
} else if (GOOGLE_APPLICATION_CREDENTIALS_JSON) {
  try {
    credentials = JSON.parse(GOOGLE_APPLICATION_CREDENTIALS_JSON); // JSON string
  } catch (e) {
    console.error('❌ Parse GOOGLE_APPLICATION_CREDENTIALS_JSON ล้มเหลว:', e.message);
    process.exit(1);
  }
} else {
  console.error('❌ ไม่พบ GOOGLE_APPLICATION_CREDENTIALS หรือ GOOGLE_APPLICATION_CREDENTIALS_JSON');
  process.exit(1);
}

/* ---------- Bot Config ---------- */
function getBotConfig(botName) {
  if (!botName) return null;
  const key = botName.toUpperCase(); // เช่น OA1_IYARA
  const id = process.env[`${key}_CHANNEL_ID`];
  const secret = process.env[`${key}_CHANNEL_SECRET`];
  if (!id || !secret) return null;
  return { botName, channelId: id, channelSecret: secret };
}

/* ---------- Google Sheets ---------- */
const auth = new google.auth.GoogleAuth({
  credentials: typeof credentials === 'string' ? undefined : credentials,
  keyFile: typeof credentials === 'string' ? credentials : undefined,
  scopes: ['https://www.googleapis.com/auth/spreadsheets']
});
const sheets = google.sheets({ version: 'v4', auth });

/* ---------- App ---------- */
const app = express();

// cookie session สำหรับ Render/HTTPS และ LINE OAuth (3rd party redirect)
app.set('trust proxy', 1);
app.use(cookieSession({
  name: 'sess',
  secret: process.env.COOKIE_SECRET || 'dev-secret-change-me',
  httpOnly: true,
  sameSite: 'none',   // ต้อง none เพื่อให้ cookie กลับมาที่ callback บนโดเมนอื่น
  secure: true        // บน Render เป็น HTTPS เสมอ
}));

// health check
app.get('/healthz', (_, res) => res.status(200).send('ok'));

/* ---------- Pages (optional) ---------- */
app.get('/', (_, res) => res.sendFile(path.join(process.cwd(), 'views', 'index.html')));
app.get('/users', (_, res) => res.sendFile(path.join(process.cwd(), 'views', 'users.html')));

/* ---------- Helpers ---------- */
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const createPkce = () => {
  const verifier = b64url(crypto.randomBytes(32));
  const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
};

/* ---------- Ensure Header ---------- */
async function ensureUsersHeader() {
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

/* ---------- Upsert User ---------- */
async function upsertUserRow({ botName, channelId, user }) {
  await ensureUsersHeader();
  const now = new Date().toISOString();
  const rowValues = [
    now, user.sub || '', user.name || '', user.email || '', user.picture || '',
    botName, channelId, now, now, 'login', JSON.stringify(user)
  ];

  let existingRow = -1;
  try {
    const all = await sheets.spreadsheets.values.get({
      spreadsheetId: SHEET_ID, range: `${SHEET_NAME}!A2:K`
    });
    const rows = all.data.values || [];
    for (let i = 0; i < rows.length; i++) {
      const [, userId, , , , rBot] = rows[i];
      if (userId === user.sub && rBot === botName) {
        existingRow = i + 2; // offset header
        break;
      }
    }
  } catch { /* ignore */ }

  if (existingRow > 0) {
    const range = `${SHEET_NAME}!A${existingRow}:K${existingRow}`;
    let old = [];
    try {
      const one = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range });
      old = one.data.values?.[0] || [];
    } catch { /* ignore */ }
    const firstSeen = old[7] || rowValues[7];
    const merged = [
      old[0] || rowValues[0], rowValues[1], rowValues[2], rowValues[3], rowValues[4],
      rowValues[5], rowValues[6], firstSeen, now, 'login', JSON.stringify(user)
    ];
    await sheets.spreadsheets.values.update({
      spreadsheetId: SHEET_ID, range, valueInputOption: 'RAW', requestBody: { values: [merged] }
    });
  } else {
    await sheets.spreadsheets.values.append({
      spreadsheetId: SHEET_ID, range: `${SHEET_NAME}!A:K`, valueInputOption: 'RAW',
      requestBody: { values: [rowValues] }
    });
  }
}

/* ---------- Debug ENV (ช่วยไล่ปัญหา 400) ---------- */
app.get('/debug/env', (req, res) => {
  const bots = (process.env.BOTS || '').split(',').map(s => s.trim()).filter(Boolean);
  const readBot = (name) => {
    const key = name.toUpperCase();
    const id = process.env[`${key}_CHANNEL_ID`];
    const secret = process.env[`${key}_CHANNEL_SECRET`];
    return {
      name,
      hasId: !!id,
      hasSecret: !!secret,
      idLooksNumeric: /^\d+$/.test(String(id || '')),
      idPreview: id ? String(id).slice(0, 4) + '...' : '(none)',
      secretPreview: secret ? String(secret).slice(0, 4) + '...' : '(none)'
    };
  };
  res.json({
    NODE_ENV: process.env.NODE_ENV,
    BASE_URL: process.env.BASE_URL,
    SHEET_ID: process.env.SHEET_ID ? '(set)' : '(missing)',
    bots,
    details: bots.map(readBot)
  });
});

/* ---------- Routes ---------- */
app.get('/login/:bot', (req, res) => {
  const botName = String(req.params.bot || '').trim();
  const cfg = getBotConfig(botName);
  if (!cfg) return res.status(400).send(`Unknown bot: ${botName}`);

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

    if (error) {
      console.error('[DEBUG callback error-param]', { botName, error, error_description });
      return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
    }

    // log state & session
    console.log('[DEBUG callback state]', JSON.stringify({
      botName,
      gotState: state,
      savedState: req.session?.[`state_${botName}`],
      hasVerifier: !!req.session?.[`verifier_${botName}`],
      baseUrl: globalThis.BASE_URL
    }));

    if (!code || state !== req.session?.[`state_${botName}`]) {
      return res.status(400).send('Invalid state/code');
    }

    // 1) Exchange token
    let tokenResp;
    try {
      tokenResp = await axios.post(
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
    } catch (err) {
      console.error('[DEBUG token error]', {
        status: err?.response?.status,
        data: err?.response?.data
      });
      return res.status(500).send('Internal error');
    }

    const { id_token } = tokenResp.data;

    // 2) Verify id_token
    let verifyResp;
    try {
      verifyResp = await axios.post(
        'https://api.line.me/oauth2/v2.1/verify',
        qs.stringify({ id_token, client_id: cfg.channelId }),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
    } catch (err) {
      console.error('[DEBUG verify error]', {
        status: err?.response?.status,
        data: err?.response?.data
      });
      return res.status(500).send('Internal error');
    }

    const user = verifyResp.data; // { sub, name, email, picture, ... }

    // 3) Upsert Google Sheet
    try {
      await upsertUserRow({ botName, channelId: cfg.channelId, user });
    } catch (err) {
      console.error('[DEBUG sheets error]', String(err));
      return res.status(500).send('Internal error');
    }

    // 4) Success page
    return res
      .status(200)
      .set('Content-Type', 'text/html; charset=utf-8')
      .send(`<h2>✅ Login success for ${botName}</h2><p>กลับไปที่ LINE ได้เลย</p>`);

  } catch (err) {
    console.error('[DEBUG callback unhandled]', err);
    return res.status(500).send('Internal error');
  }
});

/* ---------- Start ---------- */
const port = process.env.PORT || 3000;

app.listen(port, async () => {
  try {
    if (process.env.NODE_ENV === 'development' && !process.env.BASE_URL) {
      try {
        ngrok = (await import('ngrok')).default;
        const url = await ngrok.connect({
          proto: 'http',
          addr: Number(port),
          authtoken: process.env.NGROK_AUTHTOKEN || undefined,
          region: 'jp'
        });
        globalThis.BASE_URL = url;
      } catch (e) {
        console.error('NGROK_ERROR:', e?.body?.msg || e?.message || e);
        globalThis.BASE_URL = `http://localhost:${port}`;
      }
    } else {
      globalThis.BASE_URL = process.env.BASE_URL || `http://localhost:${port}`;
    }
  } finally {
    const bots = BOTS.split(',').map(s => s.trim()).filter(Boolean);
    printStartupInfo({ baseUrl: globalThis.BASE_URL, port, bots });
  }
});
