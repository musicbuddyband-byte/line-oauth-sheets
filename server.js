import 'dotenv/config';
import express from 'express';
import cookieSession from 'cookie-session';
import axios from 'axios';
import qs from 'qs';
import crypto from 'crypto';
import { google } from 'googleapis';
import path from 'node:path';
import fs from 'node:fs';
import ngrok from 'ngrok';   // 👈 เพิ่มเข้ามา

function printStartupInfo({ baseUrl, port }) {
    const box = (s) => `\n${'='.repeat(64)}\n${s}\n${'='.repeat(64)}\n`;
    const lines = [
        `✅ Server is ready`,
        `• Local Dev URL        : http://localhost:${port}`,
        `• Public BASE_URL       : ${baseUrl || '(not set)'}`,
        `• LINE Callback URL    : ${baseUrl ? baseUrl + '/callback' : '(set BASE_URL first)'}`,
        `• LINE Channel ID      : ${process.env.LINE_CHANNEL_ID}`,
        `• Google Sheet ID      : ${process.env.SHEET_ID}`,
        `• Sheet Name           : ${process.env.SHEET_NAME || 'Users'}`,
        `• NODE_ENV             : ${process.env.NODE_ENV || '(not set)'}`,
    ];
    console.log(box(lines.join('\n')));
}


const {
    LINE_CHANNEL_ID, LINE_CHANNEL_SECRET,
    BASE_URL, SHEET_ID, SHEET_NAME = 'Users',
    GOOGLE_APPLICATION_CREDENTIALS, NODE_ENV
} = process.env;

if (!LINE_CHANNEL_ID || !LINE_CHANNEL_SECRET || !SHEET_ID) {
    console.error('กรุณากรอก .env ให้ครบ (LINE_CHANNEL_ID, LINE_CHANNEL_SECRET, SHEET_ID)');
    process.exit(1);
}
if (!fs.existsSync(GOOGLE_APPLICATION_CREDENTIALS)) {
    console.error('ไม่พบไฟล์ Service Account:', GOOGLE_APPLICATION_CREDENTIALS);
    process.exit(1);
}

// Google Sheets client
const auth = new google.auth.GoogleAuth({
    keyFile: GOOGLE_APPLICATION_CREDENTIALS,
    scopes: ['https://www.googleapis.com/auth/spreadsheets']
});
const sheets = google.sheets({ version: 'v4', auth });

const app = express();
app.set('trust proxy', 1);
app.use(cookieSession({
    name: 'sess',
    secret: crypto.randomBytes(32).toString('hex'),
    httpOnly: true,
    sameSite: 'lax'
}));

// หน้าแรก
app.get('/', (_, res) => {
    res.sendFile(path.join(process.cwd(), 'views', 'index.html'));
});

// helper: PKCE
const b64url = b => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const createPkce = () => {
    const verifier = b64url(crypto.randomBytes(32));
    const challenge = b64url(crypto.createHash('sha256').update(verifier).digest());
    return { verifier, challenge };
};

// STEP1: redirect ไป LINE authorize
app.get('/login', (req, res) => {
    const state = crypto.randomUUID();
    const { verifier, challenge } = createPkce();

    req.session.state = state;
    req.session.code_verifier = verifier;

    const url = 'https://access.line.me/oauth2/v2.1/authorize?' + qs.stringify({
        response_type: 'code',
        client_id: LINE_CHANNEL_ID,
        redirect_uri: `${globalThis.BASE_URL}/callback`, // 👈 ใช้ global BASE_URL
        scope: 'openid profile email',
        state,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        prompt: 'consent'
    });
    res.redirect(url);
});

// STEP2: callback
app.get('/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;
        if (error) return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
        if (!code || state !== req.session.state) return res.status(400).send('Invalid state/code');

        const token = await axios.post('https://api.line.me/oauth2/v2.1/token', qs.stringify({
            grant_type: 'authorization_code',
            code,
            redirect_uri: `${globalThis.BASE_URL}/callback`,  // 👈 ใช้ global BASE_URL
            client_id: LINE_CHANNEL_ID,
            client_secret: LINE_CHANNEL_SECRET,
            code_verifier: req.session.code_verifier
        }), { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });

        const { id_token } = token.data;

        const verify = await axios.post('https://api.line.me/oauth2/v2.1/verify', qs.stringify({
            id_token, client_id: LINE_CHANNEL_ID
        }));
        const user = verify.data;

        // ... (โค้ดบันทึก Google Sheets เหมือนเดิม)

        res.send(`<h3>บันทึกสำเร็จ</h3>
      <pre>${JSON.stringify({ userId: user.sub, name: user.name, email: user.email }, null, 2)}</pre>
      <p><a href="/">กลับหน้าแรก</a></p>`);
    } catch (err) {
        console.error(err?.response?.status, err?.response?.data || err);
        res.status(500).send('Internal error: ' + (err?.response?.data ? JSON.stringify(err.response.data) : String(err)));
    }
});

// API: คืน users JSON
app.get('/api/users', async (_, res) => {
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
});

// หน้า UI
app.get('/users', (_, res) => {
    res.sendFile(path.join(process.cwd(), 'views', 'users.html'));
});

const port = process.env.PORT || 3000;

// เริ่ม server + ngrok (dev เท่านั้น)

app.listen(port, async () => {
    if (process.env.NODE_ENV === 'development') {
        // ถ้าใช้โหมด auto-ngrok ให้ต่อ ngrok และเซ็ต BASE_URL อัตโนมัติ
        const url = await ngrok.connect({ addr: port });
        globalThis.BASE_URL = url;
        printStartupInfo({ baseUrl: globalThis.BASE_URL, port });
    } else {
        // โหมด production ใช้จาก .env
        globalThis.BASE_URL = process.env.BASE_URL;
        printStartupInfo({ baseUrl: globalThis.BASE_URL, port });
    }
});
