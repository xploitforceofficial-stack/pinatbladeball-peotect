import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);
const SECRET_KEY = process.env.PINAT_SECRET || "default_secret_change_me";
const MAX_REQUESTS_PER_MINUTE = 20;
const DISCORD_WEBHOOK = process.env.DISCORD_WEBHOOK_URL;
const ipRequestCounts = new Map();

function checkRateLimit(ip) {
    const now = Date.now();
    const minute = 60 * 1000;
    if (!ipRequestCounts.has(ip)) {
        ipRequestCounts.set(ip, { count: 1, resetTime: now + minute });
        return { allowed: true };
    }
    const data = ipRequestCounts.get(ip);
    if (now > data.resetTime) {
        ipRequestCounts.set(ip, { count: 1, resetTime: now + minute });
        return { allowed: true };
    }
    if (data.count >= MAX_REQUESTS_PER_MINUTE) {
        return { allowed: false, reason: 'Rate Limit Exceeded' };
    }
    data.count++;
    ipRequestCounts.set(ip, data);
    return { allowed: true };
}

function validateEnv() {
    if (!process.env.MONGODB_URI) return false;
    return true;
}

async function sendDiscordLog(ip, reason, ua, details = {}) {
    if (!DISCORD_WEBHOOK) return;
    const data = {
        username: "Pinat Guard System v4",
        avatar_url: "https://files.catbox.moe/s6agav.png",
        embeds: [{
            title: "🚨 Security Alert Triggered",
            color: 15158332,
            fields: [
                { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
                { name: "🛡️ Reason", value: `\`${reason}\``, inline: true },
                { name: "📱 User Agent", value: `\`\`\`${ua.substring(0, 150)}\`\`\`` },
                { name: "🕵️ Details", value: Object.keys(details).length ? JSON.stringify(details) : "None", inline: false },
                { name: "⏰ Time", value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }) }
            ],
            footer: { text: "PinatHub Guard • Zero Tolerance" }
        }]
    };
    try {
        fetch(DISCORD_WEBHOOK, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data)
        });
    } catch (e) {}
}

function renderBlacklistPage(ip) {
    return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>404 - Not Found</title>
        <style>
            body { background: #fff; color: #000; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
            .content { max-width: 500px; padding: 20px; animation: fadeIn 0.5s ease; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            h1 { font-size: 64px; font-weight: 800; margin: 0; letter-spacing: -2px; color: #000; }
            h2 { font-size: 24px; font-weight: 700; margin: 10px 0; }
            p { color: #444; font-size: 15px; line-height: 1.6; }
            .badge { background: #ff0000; color: #fff; padding: 4px 12px; border-radius: 100px; font-size: 11px; font-weight: 800; text-transform: uppercase; margin-bottom: 20px; display: inline-block; letter-spacing: 1px; }
            .footer { margin-top: 40px; font-size: 11px; color: #999; border-top: 1px solid #eee; padding-top: 15px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="content">
            <div class="badge">PERMANENT BAN</div>
            <h1>404</h1>
            <h2>deployment not found</h2>
            <p>IP Address <b>${ip}</b> telah ditandai sebagai ancaman. Akses ditolak.</p>
            <div class="footer">
                incident_id: ${Math.random().toString(36).substring(7)}<br>
                protection_by: pinathub_guard_v4
            </div>
        </div>
    </body>
    </html>
  `;
}

function renderQuizPage(ip) {
    return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Verification</title>
        <style>
            :root { --bg: #ffffff; --fg: #111111; --accent: #eaeaea; }
            * { box-sizing: border-box; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
            body { background: var(--bg); color: var(--fg); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
            .card { width: 100%; max-width: 400px; padding: 40px; border: 1px solid var(--accent); border-radius: 16px; box-shadow: 0 20px 40px rgba(0,0,0,0.04); background: #fff; }
            h1 { font-size: 18px; font-weight: 700; margin: 0 0 8px; letter-spacing: -0.02em; text-transform: uppercase; }
            p { color: #666; font-size: 14px; line-height: 1.5; margin-bottom: 24px; }
            .option { 
                display: flex; align-items: center; width: 100%; padding: 14px 16px; margin-bottom: 8px; 
                background: #fff; border: 1px solid #ddd; border-radius: 8px; 
                font-size: 13px; text-align: left; cursor: pointer; transition: all 0.2s; font-weight: 500;
            }
            .option:hover { border-color: #000; background: #f9f9f9; transform: translateY(-1px); }
            .terminal { 
                background: #111; color: #00ff00; padding: 15px; border-radius: 8px; 
                font-family: 'Courier New', Courier, monospace; font-size: 11px; margin-top: 20px; 
                display: none; line-height: 1.4; text-align: left; white-space: pre-wrap;
            }
            .hidden { display: none !important; }
            .step { font-size: 11px; color: #999; font-family: monospace; text-transform: uppercase; margin-bottom: 4px; letter-spacing: 1px; display: block; }
            .fade { animation: fadeIn 0.4s ease forwards; }
        </style>
    </head>
    <body>
        <div class="card">
            <span class="step">security_check • stage <span id="step-num">1</span>/3</span>
            <h1 id="q-title">verifying connection...</h1>
            <p id="q-desc">system mendeteksi akses mencurigakan. mohon selesaikan verifikasi.</p>
            
            <div id="q-options" class="fade">
                <button class="option" onclick="nextStep()">saya ingin melihat source code</button>
                <button class="option" onclick="nextStep()">saya pengembang script</button>
                <button class="option" onclick="nextStep()">saya salah masuk</button>
            </div>

            <div id="log-screen" class="hidden">
                <span class="step">system_log • reporting</span>
                <div class="terminal" id="term-output"></div>
            </div>
        </div>

        <script>
            let step = 1;
            const ip = "${ip}";
            
            async function nextStep() {
                step++;
                if (step === 2) {
                    document.getElementById('step-num').innerText = '2';
                    document.getElementById('q-title').innerText = "deteksi perilaku...";
                    document.getElementById('q-desc').innerText = "menganalisis pola akses pengguna.";
                    const opts = document.getElementById('q-options');
                    opts.innerHTML = '<button class="option" onclick="nextStep()">menggunakan browser normal</button><button class="option" onclick="nextStep()">menggunakan tools otomatis</button>';
                } else if (step === 3) {
                    document.getElementById('step-num').innerText = '3';
                    document.getElementById('q-title').innerText = "proses blacklist...";
                    document.getElementById('q-desc').innerText = "mengunci permanen akses ip ini.";
                    document.getElementById('q-options').classList.add('hidden');
                    document.getElementById('log-screen').classList.remove('hidden');
                    await fetch(window.location.href, { method: 'POST' });
                    const term = document.getElementById('term-output');
                    term.style.display = 'block';
                    const logs = [
                        "> init_security_protocol...",
                        "> analyzing_user_agent: suspicious",
                        "> checking_ip_blacklist: clean",
                        "> action: adding_to_blacklist",
                        "> logging_incident: success",
                        "> status: banned_permanently"
                    ];
                    for (let i = 0; i < logs.length; i++) {
                        await new Promise(r => setTimeout(r, 600));
                        term.innerHTML += logs[i] + "\\n";
                    }
                }
            }
        </script>
    </body>
    </html>
  `;
}

export default async function handler(req, res) {
    if (!validateEnv()) return res.status(500).send('-- System Error: Configuration Missing');

    const userAgent = req.headers['user-agent'] || '';
    const referer = req.headers['referer'] || '';
    const ua = userAgent.toLowerCase();
    const ipRaw = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '0.0.0.0';
    const ip = ipRaw.split(',')[0].trim();
    const rateCheck = checkRateLimit(ip);

    if (!rateCheck.allowed) {
        await sendDiscordLog(ip, rateCheck.reason, userAgent);
        return res.status(429).send('-- Too Many Requests. Slow down, skid.');
    }

    const suspiciousUA = ['python', 'curl', 'wget', 'postman', 'httpie', 'insomnia', 'swagger', 'headless', 'phantom', 'selenium'];
    const isSpyUA = suspiciousUA.some(tool => ua.includes(tool));

    if (isSpyUA && (!referer || !referer.includes('roblox.com'))) {
        await sendDiscordLog(ip, "HTTP Spy / Scanner Detected", userAgent, { referer: referer });
        try {
            await client.connect();
            const db = client.db('pinat_protection');
            await db.collection('blacklisted_ips').updateOne(
                { ip }, 
                { $set: { reason: 'http_spy_detected', date: new Date() } }, 
                { upsert: true }
            );
        } catch(e) {} finally { await client.close(); }
        return res.status(403).send(renderBlacklistPage(ip));
    }

    const isRoblox = ua.includes('roblox') || ua.includes('wininet') || ua.includes('lua');
    
    // SMT / Fingerprinting check
    const hasAcceptLang = req.headers['accept-language'] !== undefined;
    const hasEncoding = req.headers['accept-encoding'] !== undefined;
    
    // Jika UA Roblox tapi TANPA header browser standar -> Automation / SMT / Spoofing
    if (isRoblox && (!hasAcceptLang || !hasEncoding)) {
         await sendDiscordLog(ip, "SMT / Automation / Spoofing Detected", userAgent);
         try {
            await client.connect();
            const db = client.db('pinat_protection');
            await db.collection('blacklisted_ips').updateOne(
                { ip }, 
                { $set: { reason: 'automation_detected', date: new Date() } }, 
                { upsert: true }
            );
        } catch(e) {} finally { await client.close(); }
        return res.status(403).send(renderBlacklistPage(ip));
    }

    if (isRoblox) {
        try {
            const response = await fetch('https://raw.githubusercontent.com/xploitforceofficial-stack/apocalpse3/refs/heads/main/s.lua');
            const content = await response.text();
            res.setHeader('Content-Type', 'text/plain');
            res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
            return res.status(200).send(content);
        } catch (err) {
            return res.status(500).send('-- Error loading script.');
        }
    }

    try {
        await client.connect();
        const db = client.db('pinat_protection');
        const blacklist = db.collection('blacklisted_ips');
        const blocked = await blacklist.findOne({ ip });

        if (blocked) {
            return res.status(403).send(renderBlacklistPage(ip));
        }

        const forbiddenTools = [
            'curl', 'wget', 'powershell', 'pwsh', 'vscode', 
            'insomnia', 'postman', 'python', 'python-requests', 'node-fetch', 
            'termux', 'terminal', 'axios', 'go-http-client', 'bruno', 'httpie',
            'rest-client', 'libcurl'
        ];

        const isTool = forbiddenTools.some(tool => ua.includes(tool));

        if (isTool) {
            await blacklist.insertOne({ ip, reason: 'illegal_tool_auto_ban', date: new Date() });
            await sendDiscordLog(ip, "Illegal Tool Auto-Ban", userAgent);
            return res.status(403).send(renderBlacklistPage(ip));
        }
    } catch (e) {
        console.error("DB Error:", e);
    } finally {
        if (client) await client.close(); 
    }

    // HONEYPOT TRAP
    if (req.method === 'POST') {
        try {
            await client.connect();
            const db = client.db('pinat_protection');
            await db.collection('blacklisted_ips').updateOne(
                { ip }, 
                { $set: { reason: 'honeypot_triggered', date: new Date() } }, 
                { upsert: true }
            );
            await sendDiscordLog(ip, "Honeypot Triggered (Quiz Failed)", userAgent);
        } catch(e) {} finally { await client.close(); }
        return res.status(200).json({ success: false, message: "logged" });
    }

    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderQuizPage(ip));
}
