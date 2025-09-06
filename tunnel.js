// scripts/tunnel.js
// เรียก ngrok -> ได้ URL -> อัปเดต .env (BASE_URL) -> สตาร์ท server.js

import 'dotenv/config';
import ngrok from 'ngrok';
import fs from 'fs';
import path from 'node:path';
import { spawn } from 'node:child_process';

const ROOT = process.cwd();
const ENV_PATH = path.join(ROOT, '.env');

function upsertEnvVar(text, key, value) {
    if (!text.includes(`${key}=`)) {
        return text.trimEnd() + `\n${key}=${value}\n`;
    }
    // แทนค่าบรรทัดเดิม
    const re = new RegExp(`^${key}=.*$`, 'm');
    return text.replace(re, `${key}=${value}`);
}

async function main() {
    const port = process.env.PORT || 3000;

    // เปิด ngrok
    const authtoken = process.env.NGROK_AUTHTOKEN;
    if (!authtoken) {
        console.error('❌ ไม่พบ NGROK_AUTHTOKEN (ตั้งค่าใน .env หรือ ENV ก่อน)');
        process.exit(1);
    }
    await ngrok.authtoken(authtoken);

    const url = await ngrok.connect({ addr: port, proto: 'http' });
    console.log('🔗 ngrok URL:', url);

    // อัปเดต .env → BASE_URL
    const envText = fs.existsSync(ENV_PATH) ? fs.readFileSync(ENV_PATH, 'utf8') : '';
    const nextText = upsertEnvVar(envText, 'BASE_URL', url);
    fs.writeFileSync(ENV_PATH, nextText, 'utf8');
    console.log('📝 อัปเดต .env -> BASE_URL =', url);

    // สตาร์ท server หลังจากอัปเดต .env แล้ว
    const child = spawn('node', ['server.js'], {
        stdio: 'inherit',
        env: { ...process.env, BASE_URL: url }, // เผื่ออ่านจาก env โดยตรง
    });

    const shutdown = async () => {
        console.log('\n⏳ ปิด server และ ngrok...');
        try { child.kill('SIGINT'); } catch { }
        try { await ngrok.disconnect(); await ngrok.kill(); } catch { }
        process.exit(0);
    };

    process.on('SIGINT', shutdown);
    process.on('SIGTERM', shutdown);

    console.log(`
✅ พร้อมใช้งาน

- Public URL (หน้าแรก):     ${url}/
- LINE Callback URL:         ${url}/callback

อย่าลืมอัปเดต LINE Developers → Callback URL ให้เป็น:
${url}/callback
`);
}

main().catch(async (e) => {
    console.error('🔥 tunnel error:', e);
    try { await ngrok.kill(); } catch { }
    process.exit(1);
});
