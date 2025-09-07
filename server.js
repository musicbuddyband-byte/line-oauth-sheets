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
app.get('/callback', async (req, res) => {
    try {
        const { code, state, error, error_description } = req.query;
        if (error) return res.status(400).send(`LINE error: ${error} ${error_description || ''}`);
        if (!code || state !== req.session.state) return res.status(400).send('Invalid state/code');

        // 1) แลก token
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

        // 2) verify id_token -> ได้ข้อมูลผู้ใช้
        const verifyResp = await axios.post(
            'https://api.line.me/oauth2/v2.1/verify',
            qs.stringify({ id_token, client_id: LINE_CHANNEL_ID }),
            { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
        );
        const user = verifyResp.data; // { sub, name, email, picture, ... }

        // 3) เขียน/อัปเดต Google Sheet
        const timestamp = new Date().toISOString();
        const rowValues = [
            timestamp,
            user.sub || '',
            user.name || '',
            user.email || '',
            user.picture || '',
        ];

        // 3.1 สร้างหัวตารางถ้ายังไม่มี
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

        // 3.2 ถ้า userId มีอยู่แล้ว -> อัปเดตแถวเดิม, ถ้าไม่มีก็ append
        let existingRow = -1;
        try {
            const all = await sheets.spreadsheets.values.get({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A2:E`,
            });
            (all.data.values || []).forEach((r, i) => {
                if (r[1] === user.sub) existingRow = i + 2; // +2 เพราะเริ่มนับจาก A2
            });
        } catch (_) { }

        if (existingRow > 0) {
            // อัปเดตแถวเดิม
            await sheets.spreadsheets.values.update({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A${existingRow}:E${existingRow}`,
                valueInputOption: 'RAW',
                requestBody: { values: [rowValues] }
            });
            console.log(`[SHEETS] Updated row ${existingRow} for ${user.sub}`);
        } else {
            // เพิ่มแถวใหม่
            await sheets.spreadsheets.values.append({
                spreadsheetId: SHEET_ID,
                range: `${SHEET_NAME}!A:E`,
                valueInputOption: 'RAW',
                requestBody: { values: [rowValues] }
            });
            console.log(`[SHEETS] Appended new row for ${user.sub}`);
        }

        // 4) แสดงผลลัพธ์สวยงาม (ของเดิมคุณ) + ข้อความแจ้งรอ
        const payload = {
            userId: user.sub || '',
            name: user.name || '',
            email: user.email || '',
            picture: user.picture || ''
        };

        res
            .status(200)
            .set('Content-Type', 'text/html; charset=utf-8')
            .send(/* HTML สวยงามเดิมของคุณ ทั้งก้อนที่ส่งมาในข้อความก่อนหน้า ได้เลย */`
        ${/* ==== ใส่ HTML หน้าสำเร็จของคุณที่มีข้อความ “⏳ ระบบกำลังทำรายการ … BONNY HOME” ==== */''}
        ${/* เพื่อประหยัดพื้นที่ ตัดทอนในตัวอย่างนี้ แต่คุณเอา HTML สวยงามก้อนใหญ่ของคุณแปะกลับได้เลย */''}
      `);

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
