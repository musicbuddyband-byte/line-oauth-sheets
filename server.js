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
/* ---------- STEP 2: Callback -> Token -> Verify -> Write Sheet ---------- */
/* ---------- STEP 2: Callback -> Token -> Verify -> Write Sheet + Show Page ---------- */
app.get('/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;
        if (error) return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
        if (!code || state !== req.session.state) return res.status(400).send('Invalid state/code');

        // 1) Exchange token
        const tokenResp = await axios.post(
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
        const { id_token } = tokenResp.data;

        // 2) Verify id_token
        const verifyResp = await axios.post(
            'https://api.line.me/oauth2/v2.1/verify',
            qs.stringify({ id_token, client_id: LINE_CHANNEL_ID }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        const user = verifyResp.data; // { sub, name, email, picture, ... }

        // 3) Write to Google Sheet (create header if missing, upsert by userId)
        const timestamp = new Date().toISOString();
        const rowValues = [
            timestamp,
            user.sub || '',
            user.name || '',
            user.email || '',
            user.picture || '',
        ];

        // 3.1 header
        let haveHeader = false;
        try {
            const meta = await sheets.spreadsheets.values.get({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A1:E1`,
            });
            haveHeader = Array.isArray(meta.data.values) && meta.data.values.length > 0;
        } catch (_) { }
        if (!haveHeader) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A1:E1`,
                valueInputOption: 'RAW',
                requestBody: { values: [['timestamp', 'userId', 'displayName', 'email', 'pictureUrl']] }
            });
        }

        // 3.2 upsert
        let existingRow = -1;
        try {
            const all = await sheets.spreadsheets.values.get({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A2:E`,
            });
            (all.data.values || []).forEach((r, i) => {
                if (r[1] === user.sub) existingRow = i + 2;
            });
        } catch (_) { }
        if (existingRow > 0) {
            await sheets.spreadsheets.values.update({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A${existingRow}:E${existingRow}`,
                valueInputOption: 'RAW',
                requestBody: { values: [rowValues] }
            });
        } else {
            await sheets.spreadsheets.values.append({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A:E`,
                valueInputOption: 'RAW',
                requestBody: { values: [rowValues] }
            });
        }

        // 4) Pretty result page
        const payload = {
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
    margin:0;
    background:
      radial-gradient(1000px 600px at 10% -10%, rgba(110,231,255,.10), transparent 50%),
      radial-gradient(1000px 700px at 110% 30%, rgba(99,102,241,.12), transparent 45%),
      linear-gradient(180deg, #0b1020 0%, #0a0f22 100%);
    color:var(--text);
    font:16px/1.6 Poppins, system-ui, -apple-system, Segoe UI, Roboto, Arial;
    display:grid; place-items:center; padding:24px;
  }
  .wrap{max-width:960px; width:100%}
  .card{
    background:linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
    border:1px solid rgba(255,255,255,.08);
    box-shadow:0 30px 50px rgba(0,0,0,.35), inset 0 0 0 1px rgba(255,255,255,.04);
    border-radius:var(--radius); padding:28px; position:relative; overflow:hidden;
  }
  .hero{display:flex; gap:20px; align-items:center; padding-bottom:12px; border-bottom:1px dashed rgba(255,255,255,.12); margin-bottom:18px;}
  .badge{
    display:inline-flex; gap:8px; align-items:center;
    background:rgba(34,197,94,.12); color:#86efac; border:1px solid rgba(34,197,94,.25);
    padding:6px 10px; border-radius:999px; font-weight:600; font-size:12px; letter-spacing:.3px; text-transform:uppercase;
  }
  .title{font-size:22px; font-weight:700; margin:0}
  .muted{color:var(--muted); font-size:14px}
  .user{display:flex; gap:16px; align-items:center; margin:12px 0 6px}
  .avatar{width:56px; height:56px; border-radius:50%; object-fit:cover; flex:0 0 auto; border:2px solid rgba(255,255,255,.12); box-shadow:0 8px 20px rgba(0,0,0,.25)}
  .kv{display:grid; gap:8px; margin:12px 0 6px}
  .row{display:flex; gap:8px; align-items:baseline}
  .key{width:110px; color:var(--muted)} .val{font-weight:600; color:var(--text); word-break:break-all}
  .actions{display:flex; flex-wrap:wrap; gap:10px; margin-top:18px}
  .btn{
    appearance:none; border:1px solid rgba(255,255,255,.12);
    background:#101935; color:var(--text); padding:10px 14px; border-radius:12px;
    font-weight:600; letter-spacing:.2px; cursor:pointer;
    transition:transform .08s ease, box-shadow .15s ease, border-color .2s ease, background .2s ease;
  }
  .btn:hover{transform:translateY(-1px); border-color:rgba(110,231,255,.35); box-shadow:0 6px 18px var(--ring)}
  .btn.primary{background:linear-gradient(135deg, #3b82f6 0%, #22d3ee 100%); border-color:transparent}
  .btn.success{background:linear-gradient(135deg, #16a34a, #22c55e); border-color:transparent}
  .btn.ghost{background:transparent}
  .grid{display:grid; grid-template-columns:1fr; gap:18px}
  @media (min-width:720px){ .grid{grid-template-columns:1.1fr .9fr} }
  pre{margin:0; padding:16px; border-radius:12px; background:rgba(2,6,23,.55); border:1px solid rgba(255,255,255,.08); overflow:auto; color:#e5edff}
  .note{font-size:12px; color:var(--muted); margin-top:10px}
</style>
</head>
<body>
  <div class="wrap">
    <div class="card">
      <div class="hero">
        <span class="badge">✓ บันทึกสำเร็จ</span>
        <h1 class="title">เข้าสู่ระบบด้วย LINE สำเร็จ กรุณารอเจ้าหน้าที่สักครู่ ⏳</h1>
      </div>

      <div class="grid">
        <section>
          <div class="user">
            <img class="avatar" src="${payload.picture || 'https://i.imgur.com/8Km9tLL.png'}" alt="avatar"/>
            <div>
              <div style="font-size:18px; font-weight:700">${payload.name || '—'}</div>
              <div class="muted">${payload.email || '—'}</div>
            </div>
          </div>

          <div class="kv">
            <div class="row"><div class="key">User ID</div><div class="val">${payload.userId}</div></div>
            <div class="row"><div class="key">ชื่อ</div><div class="val">${payload.name || '—'}</div></div>
            <div class="row"><div class="key">อีเมล</div><div class="val">${payload.email || '—'}</div></div>
          </div>

          <div class="actions">
            <a class="btn ghost" href="/">← กลับหน้าแรก</a>
            <button class="btn success" onclick="closeWin()">ปิดหน้านี้</button>
          </div>
          <div class="note">ปุ่ม “ปิดหน้านี้” จะปิดหน้าต่าง (หรือ <code>liff.closeWindow()</code> หากเปิดใน LIFF)</div>
        </section>

        <section>
          <div class="muted" style="margin-bottom:8px;font-weight:600">ข้อมูลที่ส่งกลับ</div>
          <pre>${JSON.stringify(payload, null, 2)}</pre>
          <p class="note" style="color:#facc15; font-size:13px; margin-top:12px;">
            ⚠️ ระบบกำลังทำรายการ กรุณารอสักครู่ หากนานเกิน 24 ชั่วโมง กรุณาติดต่อพนักงาน <b>BONNY HOME</b>
          </p>
        </section>
      </div>
    </div>
  </div>
  <script>
    function closeWin(){
      try {
        if (window.liff && typeof liff.closeWindow === 'function') { liff.closeWindow(); return; }
      } catch(e){}
      window.close();
    }
  </script>
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
