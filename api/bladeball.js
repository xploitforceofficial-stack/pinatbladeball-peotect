import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// Helper function untuk cek VPN/Proxy via ipapi.is
async function checkVpnProxy(ip) {
  const API_KEY = 'c5473140651f84c8d9ba';
  try {
    const response = await fetch(`https://api.ipapi.is?q=${ip}&key=${API_KEY}`);
    const data = await response.json();
    return {
      is_vpn: data?.is_vpn || false,
      is_proxy: data?.is_proxy || false,
      is_datacenter: data?.is_datacenter || false,
      country: data?.location?.country || 'Unknown',
      city: data?.location?.city || 'Unknown'
    };
  } catch (err) {
    console.error('ipapi.is error:', err);
    return { is_vpn: false, is_proxy: false, is_datacenter: false, country: 'Unknown', city: 'Unknown' };
  }
}

// Fungsi generate salted token (Base64 dari Jam_UTC + PINAT_SALT_77)
function generateSaltedToken() {
  const utcHour = Math.floor(Date.now() / 3600000); // Jam UTC dalam bentuk integer
  const rawString = utcHour + "PINAT_SALT_77";
  return Buffer.from(rawString).toString('base64');
}

// Fungsi validasi token
function validateToken(token) {
  if (!token) return false;
  const expectedToken = generateSaltedToken();
  return token === expectedToken;
}

// Enhanced Discord logging dengan detail lengkap
async function sendDiscordLog(ip, reason, ua, hwid = null, country = null, city = null) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Reason", value: `\`${reason}\``, inline: true },
    { name: "📱 User Agent", value: `\`${ua.substring(0, 100)}\`` },
    { name: "⏰ Timestamp", value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }) }
  ];

  // Tambahkan HWID jika ada
  if (hwid) {
    fields.push({ name: "🔑 HWID", value: `\`${hwid}\``, inline: true });
  }

  // Tambahkan country & city jika ada
  if (country && country !== 'Unknown') {
    fields.push({ name: "🌍 Country", value: `\`${country}\``, inline: true });
  }
  if (city && city !== 'Unknown') {
    fields.push({ name: "🏙️ City", value: `\`${city}\``, inline: true });
  }

  const data = {
    username: "Pinat Guard System v4",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 Skidder Detected & Banned!",
      color: 15158332,
      fields: fields,
      footer: { text: "PinatHub Security Protection v4 - AntiVPN & HWID Ban" }
    }]
  };

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
  } catch (e) {
    console.error("Webhook error:", e);
  }
}

// Blacklist page (sama seperti sebelumnya)
function renderBlacklistPage(ip, hwid = null) {
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>404 - deployment not found</title>
        <style>
            body { background: #fff; color: #000; font-family: -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
            .content { max-width: 500px; padding: 20px; }
            h1 { font-size: 64px; font-weight: 700; margin: 0; letter-spacing: -2px; }
            h2 { font-size: 24px; font-weight: 600; margin: 10px 0; }
            p { color: #666; font-size: 14px; line-height: 1.6; }
            .badge { background: #ff0000; color: #fff; padding: 4px 12px; border-radius: 100px; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 20px; display: inline-block; }
            .footer { margin-top: 40px; font-size: 12px; color: #ccc; border-top: 1px solid #eaeaea; padding-top: 20px; font-family: monospace; }
        </style>
    </head>
    <body>
        <div class="content">
            <div class="badge">permanent ban</div>
            <h1>404</h1>
            <h2>yah, kena mental ya?</h2>
            <p>selamat! ${hwid ? 'device kamu' : `ip kamu <b>${ip}</b>`} resmi kami tandai sebagai <b>skidder profesional</b>. akses ke api ini sudah ditutup selamanya buat kamu. mending waktu lu dipake buat belajar mtk daripada nyoba bongkar asset orang. 😊</p>
            <div class="footer">
                incident_report_id: ${Math.random().toString(36).substring(7)}<br>
                status: blacklisted_by_pinathub
            </div>
        </div>
    </body>
    </html>
  `;
}

export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const xForwardedFor = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const xHwid = req.headers['x-hwid']; // HWID dari client
  const clientToken = req.headers['x-pinat-auth']; // Token autentikasi

  // REGION LOCK: Indonesia Only (gunakan header Vercel)
  const countryCode = req.headers['x-vercel-ip-country'] || '';
  if (countryCode !== 'ID') {
    console.log(`Blocked non-Indonesia access: ${countryCode} from IP ${xForwardedFor}`);
    return res.status(403).send('Access Denied: This service is only available in Indonesia.');
  }

  // 1. DETEKSI ROBLOX (BYPASS SEMUA)
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');

  if (isRoblox) {
    try {
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-5');
      let content = await response.text();
      
      // PAYLOAD OBFUSCATION: Ubah script ke Hex String
      const hexEncoded = Buffer.from(content).toString('hex');
      
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(hexEncoded);
    } catch (err) {
      return res.status(500).send('2d2d205b70696e61746875622d6572726f725d3a20736f75726365206f66666c696e652e');
    }
  }

  // 2. LOGIKA UNTUK NON-ROBLOX (BROWSER / TOOLS)
  const forbiddenTools = [
    'curl', 'wget', 'powershell', 'powershell-core', 'pwsh', 'vscode', 
    'insomnia', 'postman', 'python', 'python-requests', 'node-fetch', 
    'termux', 'terminal', 'axios', 'go-http-client', 'bruno', 'httpie',
    'rest-client', 'libcurl', 'wininet'
  ];

  const isForbidden = forbiddenTools.some(tool => userAgent.includes(tool));

  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('blacklisted_ips');

    // A. Cek blacklist berdasarkan IP ATAU HWID (enhanced)
    const queryConditions = [{ ip: xForwardedFor }];
    if (xHwid) {
      queryConditions.push({ hwid: xHwid });
    }
    
    const blocked = await blacklist.findOne({ $or: queryConditions });
    if (blocked) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, blocked.hwid));
    }

    // B. VALIDASI TOKEN (Salted Token Handshake)
    if (!validateToken(clientToken)) {
      // Token invalid -> anggap HTTP Get Hook / skidder
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        hwid: xHwid || null,
        reason: 'invalid_token_http_hook', 
        date: new Date() 
      });
      
      await sendDiscordLog(xForwardedFor, "Invalid Token (HTTP Hook Attempt)", userAgent, xHwid);
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // C. CEK VPN/PROXY/DATACENTER via ipapi.is
    const vpnCheck = await checkVpnProxy(xForwardedFor);
    if (vpnCheck.is_vpn || vpnCheck.is_proxy || vpnCheck.is_datacenter) {
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        hwid: xHwid || null,
        reason: `vpn_proxy_detected: vpn=${vpnCheck.is_vpn} proxy=${vpnCheck.is_proxy} dc=${vpnCheck.is_datacenter}`, 
        date: new Date() 
      });
      
      await sendDiscordLog(xForwardedFor, "VPN/Proxy/DC Detected", userAgent, xHwid, vpnCheck.country, vpnCheck.city);
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // D. Langsung blacklist jika pakai tool terminal/ilegal
    if (isForbidden) {
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        hwid: xHwid || null,
        reason: 'illegal_tool_detected', 
        date: new Date() 
      });
      
      await sendDiscordLog(xForwardedFor, "Illegal Tool Detection", userAgent, xHwid, vpnCheck.country, vpnCheck.city);

      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // E. Jika buka di browser, tampilkan UI Kuis
    if (req.method === 'POST') {
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        hwid: xHwid || null,
        reason: 'failed_quiz_skidder', 
        date: new Date() 
      });
      
      await sendDiscordLog(xForwardedFor, "Failed Quiz (Intentional Skidder)", userAgent, xHwid, vpnCheck.country, vpnCheck.city);

      return res.status(200).json({ status: 'blacklisted' });
    }

    // Tampilkan Halaman Kuis (sama seperti sebelumnya)
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html lang="id">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>deployment verification</title>
          <style>
              :root { --bg: #fff; --fg: #000; --accents-2: #eaeaea; }
              * { box-sizing: border-box; font-family: -apple-system, system-ui, sans-serif; }
              body { background: var(--bg); color: var(--fg); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
              .card { width: 100%; max-width: 450px; padding: 40px; border: 1px solid var(--accents-2); border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.05); }
              .step { font-size: 12px; color: #888; margin-bottom: 8px; }
              h1 { font-size: 20px; font-weight: 600; margin: 0 0 10px; letter-spacing: -0.02em; }
              p { color: #666; font-size: 14px; line-height: 1.5; margin-bottom: 25px; }
              .option { 
                  display: block; width: 100%; padding: 12px 16px; margin-bottom: 8px; 
                  background: #fff; border: 1px solid var(--accents-2); border-radius: 6px; 
                  font-size: 13px; text-align: left; cursor: pointer; transition: 0.2s;
              }
              .option:hover { border-color: #000; background: #fafafa; }
              .terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 11px; margin-top: 20px; display: none; line-height: 1.4; }
              .hidden { display: none; }
          </style>
      </head>
      <body>
          <div class="card">
              <svg width="25" height="22" viewBox="0 0 76 65" fill="#000"><path d="M37.5274 0L75.0548 65H0L37.5274 0Z"/></svg>
              
              <div id="q-stage">
                  <div class="step">security_check • stage <span id="step-num">1</span>/3</div>
                  <h1 id="q-text">deteksi akses ilegal..</h1>
                  <p id="q-sub">kami mendeteksi kaka pake browser. silakan verifikasi kalo kaka bukan skidder.</p>
                  <div id="options-alt">
                      <button class="option" onclick="next()">saya cuma mau liat source code kak</button>
                      <button class="option" onclick="next()">saya mau ganti nama owner scriptnya</button>
                      <button class="option" onclick="next()">saya ga sengaja kepencet inspect element</button>
                  </div>
              </div>

              <div id="log-stage" class="hidden">
                  <div class="step">reporting_incident • database_v3</div>
                  <h1>memproses laporan..</h1>
                  <p>jawaban kaka udah di-log. sistem lagi ngirim metadata ke owner buat di ban permanen.</p>
                  <div class="terminal" id="term"></div>
                  <button class="option" style="margin-top:20px; text-align:center;" onclick="location.reload()">tutup</button>
              </div>
          </div>

          <script>
              let s = 1;
              async function next() {
                  if(s < 3) {
                      s++;
                      document.getElementById('step-num').innerText = s;
                      document.getElementById('q-text').innerText = s === 2 ? "siapa idola para skidder?" : "apa cita-cita kaka?";
                      const opts = document.getElementById('options-alt');
                      if(s === 2) {
                          opts.innerHTML = '<button class="option" onclick="next()">bang rafael (pencipta skid)</button><button class="option" onclick="next()">pencuri script random di yt</button>';
                      } else {
                          opts.innerHTML = '<button class="option" onclick="next()">jadi tukang copas profesional</button><button class="option" onclick="next()">pensiun trus belajar mtk</button>';
                      }
                  } else {
                      await fetch(window.location.href, { method: 'POST' });

                      document.getElementById('q-stage').classList.add('hidden');
                      document.getElementById('log-stage').classList.remove('hidden');
                      const term = document.getElementById('term');
                      term.style.display = 'block';
                      const logs = [
                          "> target_ip: ${xForwardedFor}",
                          "> status: skidder_confirmed",
                          "> database: writing_blacklist...",
                          "> reporting_to_owner: success",
                          "> access_denied: true"
                      ];
                      let i = 0;
                      const iv = setInterval(() => {
                          term.innerHTML += logs[i] + "<br>";
                          i++; if(i >= logs.length) clearInterval(iv);
                      }, 600);
                  }
              }
          </script>
      </body>
      </html>
    `);

  } catch (err) {
    console.error(err);
    return res.status(500).send('2d2d205b70696e61746875622d6572726f725d3a20696e7465726e616c20736572766572206572726f722e');
  }
}
