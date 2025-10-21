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

// ตรวจสอบ credentials: ลองทั้งไฟล์และ JSON
let credentials;
if (GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(GOOGLE_APPLICATION_CREDENTIALS)) {
  credentials = GOOGLE_APPLICATION_CREDENTIALS; // ใช้ path ไฟล์
} else if (GOOGLE_APPLICATION_CREDENTIALS_JSON) {
  try {
    credentials = JSON.parse(GOOGLE_APPLICATION_CREDENTIALS_JSON); // ใช้ JSON string
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
  const key = botName.toUpperCase();
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
app.set('trust proxy', 1);
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-me';
app.use(cookieSession({
  name: 'sess',
  secret: COOKIE_SECRET,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production'
}));

// ✅ health check route
app.get('/healthz', (_, res) => res.status(200).send('ok'));

/* ---------- Pages ---------- */
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
      const [_, userId, , , , rBot] = rows[i];
      if (userId === user.sub && rBot === botName) {
        existingRow = i + 2;
        break;
      }
    }
  } catch { }

  if (existingRow > 0) {
    const range = `${SHEET_NAME}!A${existingRow}:K${existingRow}`;
    const one = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range });
    const old = one.data.values?.[0] || [];
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

app.get('/callback/:bot', async (req, res) => {
  const botName = String(req.params.bot || '').trim();
  const cfg = getBotConfig(botName);
  if (!cfg) return res.status(400).send(`Unknown bot: ${botName}`);
  try {
    const { code, state, error } = req.query;
    if (error) return res.status(400).send(`LINE error: ${error}`);
    if (!code || state !== req.session[`state_${botName}`]) return res.status(400).send('Invalid state/code');
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
    const verifyResp = await axios.post(
      'https://api.line.me/oauth2/v2.1/verify',
      qs.stringify({ id_token, client_id: cfg.channelId }),
      { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    await upsertUserRow({ botName, channelId: cfg.channelId, user: verifyResp.data });
    res.send(`<h2>✅ Login success for ${botName}</h2><p>กลับไปที่ LINE ได้เลย</p>`);
  } catch (err) {
    console.error('[callback error]', err?.response?.data || err);
    res.status(500).send('Internal Error');
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
    printStartupInfo({
      baseUrl: globalThis.BASE_URL,
      port,
      bots: BOTS.split(',').map(s => s.trim()).filter(Boolean)
    });
  }
});