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
function printStartupInfo({ baseUrl, port }) {
    const box = (s) => `\n${'='.repeat(64)}\n${s}\n${'='.repeat(64)}\n`;
    const lines = [
        `✅ Server is ready`,
        `• Local Dev URL        : http://localhost:${port}`,
        `• Public BASE_URL      : ${baseUrl || '(not set)'}`,
        `• LINE Callback URL    : ${baseUrl ? baseUrl + '/callback' : '(set BASE_URL first)'}`,
        `• LINE Channel ID      : ${process.env.LINE_CHANNEL_ID}`,
        `• Google Sheet ID      : ${process.env.SHEET_ID}`,
        `• Sheet Name           : ${process.env.SHEET_NAME || 'Users'}`,
        `• NODE_ENV             : ${process.env.NODE_ENV || '(not set)'}`
    ];
    console.log(box(lines.join('\n')));
}

/* ---------- ENV ---------- */
const {
    LINE_CHANNEL_ID, LINE_CHANNEL_SECRET,
    SHEET_ID, SHEET_NAME = 'Users',
    GOOGLE_APPLICATION_CREDENTIALS
} = process.env;

if (!LINE_CHANNEL_ID || !LINE_CHANNEL_SECRET || !SHEET_ID) {
    console.error('กรุณากรอก .env ให้ครบ (LINE_CHANNEL_ID, LINE_CHANNEL_SECRET, SHEET_ID)');
    process.exit(1);
}
if (!GOOGLE_APPLICATION_CREDENTIALS || !fs.existsSync(GOOGLE_APPLICATION_CREDENTIALS)) {
    console.error('ไม่พบไฟล์ Service Account:', GOOGLE_APPLICATION_CREDENTIALS);
    process.exit(1);
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
// ใช้ secret จาก ENV (อย่าใช้ random ทุกครั้ง)
const COOKIE_SECRET = process.env.COOKIE_SECRET || 'dev-secret-change-me';

app.use(cookieSession({
    name: 'sess',
    secret: COOKIE_SECRET,
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production'  // ใช้ secure cookie บน https
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

/* ---------- STEP 1: LINE authorize ---------- */
app.get('/login', (req, res) => {
    const state = crypto.randomUUID();
    const { verifier, challenge } = createPkce();

    req.session.state = state;
    req.session.code_verifier = verifier;

    const url = 'https://access.line.me/oauth2/v2.1/authorize?' + qs.stringify({
        response_type: 'code',
        client_id: LINE_CHANNEL_ID,
        redirect_uri: `${globalThis.BASE_URL}/callback`,
        scope: 'openid profile email',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        prompt: 'consent'
    });

    res.redirect(url);
});

/* ---------- STEP 2: Callback -> Token -> Verify -> Write Sheet ---------- */
app.get('/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;
        if (error) return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
        if (!code || state !== req.session.state) return res.status(400).send('Invalid state/code');

        // Exchange token
        const token = await axios.post(
            'https://api.line.me/oauth2/v2.1/token',
            qs.stringify({
                grant_type: 'authorization_code',
                code,
                redirect_uri: `${globalThis.BASE_URL}/callback`,
                client_id: LINE_CHANNEL_ID,
                client_secret: LINE_CHANNEL_SECRET,
                code_verifier: req.session.code_verifier
            }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );

        // Verify id_token -> payload includes email/name/picture (ถ้า scope อนุญาต)
        const { id_token } = token.data;
        const verify = await axios.post(
            'https://api.line.me/oauth2/v2.1/verify',
            qs.stringify({ id_token, client_id: LINE_CHANNEL_ID })
        );
        const user = verify.data; // { sub, name, email, picture, ... }

        // Ensure header exists
        const headerRange = `${SHEET_NAME}!A1:E1`;
        const meta = await sheets.spreadsheets.values.get({ spreadsheetId: SHEET_ID, range: headerRange }).catch(() => null);
        if (!meta?.data?.values) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: SHEET_ID,
                range: headerRange,
                valueInputOption: 'RAW',
                requestBody: { values: [['timestamp', 'userId', 'displayName', 'email', 'pictureUrl']] }
            });
        }

        // Upsert by userId
        const all = await sheets.spreadsheets.values.get({
            spreadsheetId: SHEET_ID,
            range: `${SHEET_NAME}!A2:E`
        });
        let rowIndex = -1;
        (all.data.values || []).forEach((r, i) => { if (r[1] === user.sub) rowIndex = i + 2; });

        const row = [[
            new Date().toISOString(),
            user.sub || '',
            user.name || '',
            user.email || '',
            user.picture || ''
        ]];

        if (rowIndex > 0) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A${rowIndex}:E${rowIndex}`,
                valueInputOption: 'RAW',
                requestBody: { values: row }
            });
        } else {
            await sheets.spreadsheets.values.append({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A:E`,
                valueInputOption: 'RAW',
                requestBody: { values: row }
            });
        }

        /* ---------- Pretty success page (HTML template) ---------- */
        const successHtml = `
<!doctype html>
<html lang="th">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>บันทึกสำเร็จ • LINE → Google Sheet</title>
<style>
  :root{
    --bg:#0f172a; --card:#111827; --muted:#94a3b8; --brand:#22c55e;
    --txt:#e5e7eb;
  }
  *{box-sizing:border-box}
  html,body{height:100%;margin:0}
  body{
    display:flex;align-items:center;justify-content:center;
    background:
      radial-gradient(1200px 600px at 20% -10%, #22c55e20, transparent 60%),
      radial-gradient(800px 500px at 80% 110%, #60a5fa20, transparent 60%),
      var(--bg);
    font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji";
    color:var(--txt); padding:28px;
  }
  .card{
    width:min(920px, 96vw);
    background:linear-gradient(#0000,#0000) padding-box,
               linear-gradient(135deg, #22c55e80, #60a5fa80) border-box;
    border:1px solid transparent; border-radius:24px; padding:28px;
    box-shadow:0 20px 60px #0008, inset 0 0 0 1px #ffffff0a;
    backdrop-filter: blur(6px); position:relative;
  }
  .title{display:flex;gap:12px;align-items:center;margin:0 0 14px;
    font-size:clamp(20px,3.2vw,28px);font-weight:700}
  .badge{font:600 12px/1.1 ui-sans-serif; color:#10b981;background:#10b9811a;
    border:1px solid #10b98140; padding:7px 9px; border-radius:999px}
  .subtitle{margin:0 0 18px;color:#94a3b8;font-size:14px}
  pre{background:#0b1220;border:1px solid #ffffff10;border-radius:16px;
    padding:18px;overflow:auto;margin:0 0 18px;max-height:40vh}
  .row{display:flex;flex-wrap:wrap;gap:12px}
  .btn{display:inline-flex;align-items:center;gap:10px;
    padding:12px 14px;border-radius:12px;border:1px solid #ffffff20;
    background:#ffffff08;color:var(--txt);text-decoration:none;font-weight:600;
    transition:.2s ease}
  .btn:hover{transform:translateY(-1px);box-shadow:0 8px 22px #0006}
  .btn.brand{background:linear-gradient(135deg,#22c55e,#16a34a);border-color:#16a34a}
  .btn.ghost{background:transparent}
  .tiny{color:#9ca3af;font-size:12px;margin-top:10px}
</style>
</head>
<body>
  <main class="card" role="main" aria-live="polite">
    <h1 class="title">✅ บันทึกสำเร็จ <span class="badge">LINE → Google Sheet</span></h1>
    <p class="subtitle">ระบบได้บันทึกข้อมูลของคุณลงในชีตเรียบร้อยแล้ว</p>
    <pre id="data" aria-label="User JSON"></pre>
    <div class="row">
      <a class="btn brand" href="/">กลับหน้าแรก</a>
      <a class="btn" href="/users">ดูรายชื่อทั้งหมด</a>
      <button class="btn ghost" id="closeBtn" type="button">ปิดแล้วกลับไปแชท LINE</button>
    </div>
    <p class="tiny">ถ้าเปิดใน LIFF/LINE ให้กด “ปิดแล้วกลับไปแชท”</p>
  </main>
  <script>
    const payload = ${JSON.stringify({ userId: user.sub, name: user.name, email: user.email })};
    document.getElementById('data').textContent = JSON.stringify(payload, null, 2);
    document.getElementById('closeBtn').addEventListener('click', async () => {
      try { if (window.liff && liff.isInClient()) await liff.closeWindow();
            else window.location.href = '/'; }
      catch { window.location.href = '/'; }
    });
  </script>
</body>
</html>`;
        return res.status(200).send(successHtml);
    } catch (err) {
        console.error(err?.response?.status, err?.response?.data || err);
        res.status(500).send('Internal error: ' + (err?.response?.data ? JSON.stringify(err.response.data) : String(err)));
    }
});

/* ---------- API: get users JSON ---------- */
app.get('/api/users', async (_, res) => {
    try {
        const { data } = await sheets.spreadsheets.values.get({
            spreadsheetId: SHEET_ID,
            range: `${SHEET_NAME}!A1:E`
        });
        const rows = data.values || [];
        const header = rows[0] || ['timestamp', 'userId', 'displayName', 'email', 'pictureUrl'];
        const items = rows.slice(1).map(r => ({
            timestamp: r[0] || '',
            userId: r[1] || '',
            displayName: r[2] || '',
            email: r[3] || '',
            pictureUrl: r[4] || ''
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
        const url = await ngrok.connect({ addr: port });
        globalThis.BASE_URL = url;
        printStartupInfo({ baseUrl: globalThis.BASE_URL, port });
    } else {
        globalThis.BASE_URL = process.env.BASE_URL;
        printStartupInfo({ baseUrl: globalThis.BASE_URL, port });
    }
});
