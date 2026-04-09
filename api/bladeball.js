import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// Konfigurasi PIApi
const PIAPI_KEY = "c5473140651f84c8d9ba";
const PIAPI_BASE_URL = "https://piapi.org/api";

// WHITELIST IP (Aman total - tidak kena blacklist apapun)
const WHITELIST_IPS = [
  '202.58.78.11',     // IP Owner
  '202.58.78.9',      // Range IP
  '202.58.78.13',     // Range IP
  '127.0.0.1',        // Localhost
  '::1'               // IPv6 Localhost
];

// Fungsi untuk cek whitelist
function isWhitelisted(ip) {
  return WHITELIST_IPS.includes(ip);
}

// Fungsi untuk mendapatkan data dari PIApi
async function getPiApiData(ip) {
  try {
    const response = await fetch(`${PIAPI_BASE_URL}/ip/intel`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': PIAPI_KEY
      },
      body: JSON.stringify({ ip: ip })
    });
    
    if (response.ok) {
      const data = await response.json();
      return data;
    }
  } catch (e) {
    console.error("PIApi error:", e);
  }
  return null;
}

// Fungsi untuk mendeteksi proxy/VPN dari data PIApi
function detectProxyVpn(piData) {
  if (!piData) return null;
  
  if (piData.is_proxy) return 'Proxy';
  if (piData.is_vpn) return 'VPN';
  if (piData.is_tor) return 'TOR';
  if (piData.is_datacenter && !piData.company?.name?.includes('Google')) return 'Datacenter/Proxy';
  
  return null;
}

// DAFTAR BLACKLIST TOOLS (FOKUS: PowerShell, Terminal, Termux, dll)
const FORBIDDEN_TOOLS = [
  // Terminal/Shell Tools (PRIORITAS)
  'powershell', 'pwsh', 'powershell-core', 'cmd', 'command prompt',
  'terminal', 'termux', 'bash', 'zsh', 'sh', 'ksh', 'fish', 'dash',
  'xterm', 'konsole', 'gnome-terminal', 'alacritty', 'kitty',
  
  // HTTP Clients
  'curl', 'wget', 'fetch', 'httpie', 'xh', 'hurl', 'restclient',
  'postman', 'insomnia', 'bruno', 'hoppscotch', 'paw', 'rested',
  
  // Programming Languages HTTP
  'python', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'http.client',
  'node-fetch', 'axios', 'superagent', 'got', 'request', 'undici',
  'php', 'curl.php', 'java', 'okhttp', 'apache-httpclient',
  'ruby', 'net-http', 'faraday', 'go-http-client', 'rust-reqwest',
  
  // Automation/Bot Tools
  'selenium', 'puppeteer', 'playwright', 'cypress', 'webdriver',
  'headless', 'phantomjs', 'casperjs', 'zombie.js', 'nightmare',
  
  // Security Tools
  'nmap', 'masscan', 'zmap', 'hydra', 'medusa', 'ncrack',
  'sqlmap', 'burpsuite', 'owasp', 'zap', 'nikto', 'wpscan',
  'dirb', 'gobuster', 'ffuf', 'wfuzz', 'dirbuster',
  
  // Download Tools
  'aria2', 'axel', 'wget2', 'lwp-request', 'gdown', 'youtube-dl',
  'yt-dlp', 'ffmpeg', 'rtmpdump', 'streamlink',
  
  // Testing Tools
  'ab', 'siege', 'wrk', 'vegeta', 'hey', 'boom', 'jmeter',
  'gatling', 'locust', 'k6', 'artillery', 'tsung',
  
  // Crawler/Spider
  'scrapy', 'beautifulsoup', 'crawler', 'spider', 'bot'
];

// Fungsi untuk mendeteksi forbidden tools
function detectForbiddenTool(userAgent) {
  const ua = userAgent.toLowerCase();
  
  // Prioritas utama: PowerShell, Terminal, Termux
  const highPriority = ['powershell', 'pwsh', 'terminal', 'termux', 'cmd', 'bash', 'zsh'];
  
  for (const tool of highPriority) {
    if (ua.includes(tool)) {
      return { tool, priority: 'HIGH', type: 'terminal/shell' };
    }
  }
  
  // Tools lainnya
  for (const tool of FORBIDDEN_TOOLS) {
    if (ua.includes(tool)) {
      return { tool, priority: 'NORMAL', type: 'other' };
    }
  }
  
  return null;
}

// Fungsi untuk mendapatkan IP asli
function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const cfIP = req.headers['cf-connecting-ip'];
  const trueIP = req.headers['true-client-ip'];
  
  let ip = forwarded?.split(',')[0] || realIP || cfIP || trueIP || req.socket.remoteAddress;
  
  // Hapus prefix IPv6 jika ada
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  
  return ip;
}

// FUNGSI: Kirim log ke Discord Webhook dengan data PIApi
async function sendDiscordLog(ip, reason, ua, toolInfo = null, piData = null, additionalInfo = {}) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Violation", value: `\`${reason}\``, inline: true },
    { name: "🔧 User Agent", value: `\`${ua.substring(0, 100)}\``, inline: false }
  ];
  
  // Tambah info tool jika ada
  if (toolInfo) {
    fields.push({ 
      name: "⚠️ Detected Tool", 
      value: `\`${toolInfo.tool}\` (${toolInfo.priority} priority)`, 
      inline: true 
    });
  }
  
  // Tambah data dari PIApi jika ada
  if (piData) {
    const proxyVpnDetect = detectProxyVpn(piData);
    if (proxyVpnDetect) {
      fields.push({ 
        name: "🚫 Proxy/VPN Detected", 
        value: `\`${proxyVpnDetect}\``, 
        inline: true 
      });
    }
    
    fields.push(
      { name: "📍 Location", value: `${piData.location?.city || 'Unknown'}, ${piData.location?.country_code || 'Unknown'}`, inline: true },
      { name: "🏢 ISP", value: piData.company?.name || piData.asn?.org || "Unknown", inline: true },
      { name: "⚠️ Risk", value: `DC: ${piData.is_datacenter ? 'Yes' : 'No'}\nProxy: ${piData.is_proxy ? 'Yes' : 'No'}\nVPN: ${piData.is_vpn ? 'Yes' : 'No'}`, inline: true }
    );
  }
  
  if (additionalInfo.extra) {
    fields.push({ name: "📝 Additional Info", value: additionalInfo.extra });
  }
  
  fields.push({ 
    name: "⏰ Timestamp", 
    value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }) 
  });
  
  const data = {
    username: "🛡️ Pinat Guard System Pro",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 SKIDDER DETECTED & BANNED!",
      color: 15158332,
      fields: fields,
      footer: { text: "PinatHub Security Protection v5 | PIApi Enhanced" },
      timestamp: new Date().toISOString()
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

// Halaman Blacklist dengan style Vercel
function renderBlacklistPage(ip, reason, toolDetected = null, piData = null) {
  const toolMessage = toolDetected ? `🔧 Tool terdeteksi: ${toolDetected.tool.toUpperCase()}` : '';
  const proxyMessage = piData && detectProxyVpn(piData) ? `🚫 ${detectProxyVpn(piData)} DETECTED` : '';
  
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>403 - Access Denied</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-error: #ff0000; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
            .container { max-width: 600px; width: 100%; }
            .card { border: 1px solid var(--accents-2); border-radius: 12px; padding: 48px 32px; background: var(--geist-background); box-shadow: 0 8px 30px rgba(0,0,0,0.05); text-align: center; }
            .badge { display: inline-block; background: var(--geist-error); color: white; font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 100px; margin-bottom: 24px; text-transform: uppercase; letter-spacing: 0.5px; }
            h1 { font-size: 64px; font-weight: 700; letter-spacing: -2px; margin-bottom: 16px; }
            h2 { font-size: 20px; font-weight: 600; margin-bottom: 12px; }
            p { color: var(--accents-3); font-size: 14px; line-height: 1.6; margin-bottom: 24px; }
            .ip-box { background: var(--accents-1); border: 1px solid var(--accents-2); border-radius: 8px; padding: 12px; font-family: monospace; font-size: 13px; margin: 20px 0; word-break: break-all; }
            .info-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 20px 0; text-align: left; }
            .info-item { background: var(--accents-1); padding: 10px; border-radius: 6px; }
            .info-label { font-size: 11px; font-weight: 600; text-transform: uppercase; color: var(--accents-3); margin-bottom: 4px; }
            .info-value { font-size: 13px; font-family: monospace; }
            hr { border: none; border-top: 1px solid var(--accents-2); margin: 24px 0; }
            .footer { font-size: 11px; color: var(--accents-3); font-family: monospace; }
            @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
            .blink { animation: blink 1s infinite; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="badge">⚠️ PERMANENT BAN</div>
                <h1>403</h1>
                <h2 style="color: var(--geist-error);">Access Denied</h2>
                <p>IP address Anda telah ditandai sebagai <strong>skidder</strong> dan diblokir secara permanen.</p>
                
                <div class="ip-box">
                    <strong>Your IP:</strong> ${ip}
                </div>
                
                ${toolMessage || proxyMessage ? `
                <div class="info-grid">
                    ${toolMessage ? `
                    <div class="info-item">
                        <div class="info-label">Detected Tool</div>
                        <div class="info-value">${toolDetected?.tool.toUpperCase() || 'Unknown'}</div>
                    </div>
                    ` : ''}
                    ${proxyMessage ? `
                    <div class="info-item">
                        <div class="info-label">Security Flag</div>
                        <div class="info-value">${proxyMessage}</div>
                    </div>
                    ` : ''}
                    <div class="info-item">
                        <div class="info-label">Ban Reason</div>
                        <div class="info-value">${reason}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">Ban Type</div>
                        <div class="info-value blink">PERMANENT</div>
                    </div>
                </div>
                ` : ''}
                
                <p style="margin-top: 20px;">Mending waktu lu dipake buat belajar MTK daripada nyoba bongkar asset orang. 😊</p>
                
                <hr>
                
                <div class="footer">
                    incident_id: ${Math.random().toString(36).substring(2, 10)}<br>
                    status: blacklisted_by_pinathub<br>
                    appeal: not_available_for_skidders
                </div>
            </div>
        </div>
    </body>
    </html>
  `;
}

// Halaman Kuis dengan style Vercel
function renderQuizPage(ip) {
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Required</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-success: #0070f3; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
            .container { max-width: 500px; width: 100%; }
            .card { border: 1px solid var(--accents-2); border-radius: 12px; padding: 40px 32px; background: var(--geist-background); box-shadow: 0 8px 30px rgba(0,0,0,0.05); }
            .step { font-size: 12px; color: var(--accents-3); margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; }
            h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em; }
            .subtext { color: var(--accents-3); font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
            .option { width: 100%; padding: 12px 16px; margin-bottom: 8px; background: var(--geist-background); border: 1px solid var(--accents-2); border-radius: 8px; font-size: 14px; text-align: left; cursor: pointer; transition: all 0.2s ease; font-family: inherit; }
            .option:hover { border-color: var(--geist-foreground); background: var(--accents-1); transform: translateY(-1px); }
            .terminal { background: #000; color: #0f0; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 11px; margin-top: 24px; line-height: 1.5; display: none; }
            .hidden { display: none; }
            .vercel-icon { margin-bottom: 24px; }
            hr { border: none; border-top: 1px solid var(--accents-2); margin: 24px 0 16px; }
            .footer-text { font-size: 11px; color: var(--accents-3); text-align: center; margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="vercel-icon">
                    <svg width="25" height="22" viewBox="0 0 76 65" fill="currentColor"><path d="M37.5274 0L75.0548 65H0L37.5274 0Z"/></svg>
                </div>
                
                <div id="quiz-stage">
                    <div class="step">SECURITY CHECK • STAGE <span id="step-num">1</span>/3</div>
                    <h1 id="question">Verifikasi akses</h1>
                    <div class="subtext" id="subtext">Kami mendeteksi Anda menggunakan browser. Silakan verifikasi bahwa Anda bukan skidder.</div>
                    <div id="options-container"></div>
                </div>

                <div id="log-stage" class="hidden">
                    <div class="step">REPORTING INCIDENT</div>
                    <h1>Memproses laporan...</h1>
                    <div class="subtext">Jawaban Anda telah dicatat. Sistem sedang mengirim metadata ke owner untuk ban permanen.</div>
                    <div class="terminal" id="terminal-log"></div>
                    <hr>
                    <button class="option" onclick="location.reload()" style="text-align: center; margin-top: 16px;">Tutup</button>
                </div>
                
                <div class="footer-text">
                    protected by pinathub security
                </div>
            </div>
        </div>

        <script>
            let currentStep = 1;
            
            const questions = [
                { text: "Siapa idola para skidder?", sub: "Pilih jawaban yang paling tepat:" },
                { text: "Apa cita-cita kaka?", sub: "Jujur ya :)" }
            ];
            
            const optionsList = [
                ['Bang Rafael (pencipta skid)', 'Pencuri script random di YouTube', 'Coder yang gabut', 'Anak TI yang nyasar'],
                ['Jadi tukang copas profesional', 'Pensiun trus belajar MTK', 'Jualan script abal-abal', 'Nginjekin karya orang']
            ];
            
            function renderOptions() {
                const container = document.getElementById('options-container');
                const idx = currentStep - 1;
                container.innerHTML = '';
                optionsList[idx].forEach(opt => {
                    const btn = document.createElement('button');
                    btn.className = 'option';
                    btn.textContent = opt;
                    btn.onclick = () => nextStep();
                    container.appendChild(btn);
                });
            }
            
            function nextStep() {
                if (currentStep < 2) {
                    currentStep++;
                    document.getElementById('step-num').innerText = currentStep;
                    document.getElementById('question').innerText = questions[currentStep-1].text;
                    document.getElementById('subtext').innerText = questions[currentStep-1].sub;
                    renderOptions();
                } else {
                    finishQuiz();
                }
            }
            
            async function finishQuiz() {
                await fetch(window.location.href, { method: 'POST' });
                
                document.getElementById('quiz-stage').classList.add('hidden');
                document.getElementById('log-stage').classList.remove('hidden');
                
                const terminal = document.getElementById('terminal-log');
                terminal.style.display = 'block';
                
                const logs = [
                    "> target_ip: ${ip}",
                    "> status: skidder_confirmed",
                    "> database: writing_blacklist...",
                    "> reporting_to_owner: success",
                    "> access_denied: true",
                    "> ban_type: permanent"
                ];
                
                let i = 0;
                const interval = setInterval(() => {
                    terminal.innerHTML += logs[i] + "<br>";
                    i++;
                    if (i >= logs.length) clearInterval(interval);
                }, 600);
            }
            
            // Initialize
            document.getElementById('question').innerText = questions[0].text;
            document.getElementById('subtext').innerText = questions[0].sub;
            renderOptions();
        </script>
    </body>
    </html>
  `;
}

// MAIN HANDLER
export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const ip = getRealIP(req);
  
  // CEK WHITELIST (Prioritas tertinggi)
  if (isWhitelisted(ip)) {
    console.log(`[WHITELIST] IP ${ip} diizinkan akses penuh`);
    
    // Untuk Roblox
    if (userAgent.includes('roblox') && !userAgent.includes('robloxstudio')) {
      try {
        const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
        const content = await response.text();
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        return res.status(200).send(content);
      } catch (err) {
        return res.status(500).send('-- [pinathub-error]: source offline.');
      }
    }
    
    // Untuk browser/akses lain (tampilkan halaman khusus owner)
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="UTF-8">
          <title>Owner Access</title>
          <style>
              body { font-family: monospace; display: flex; justify-content: center; align-items: center; height: 100vh; background: #000; color: #0f0; }
              .container { text-align: center; }
              h1 { font-size: 48px; }
              .ip { background: #111; padding: 20px; border-radius: 10px; margin: 20px; }
          </style>
      </head>
      <body>
          <div class="container">
              <h1>👑 OWNER ACCESS GRANTED</h1>
              <div class="ip">
                  <p>IP: ${ip}</p>
                  <p>Status: WHITELISTED</p>
                  <p>Access: FULL</p>
              </div>
              <p>Welcome back, Master!</p>
          </div>
      </body>
      </html>
    `);
  }
  
  // 1. DETEKSI ROBLOX (BYPASS untuk non-whitelist)
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');
  
  if (isRoblox) {
    try {
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
      const content = await response.text();
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(content);
    } catch (err) {
      return res.status(500).send('-- [pinathub-error]: source offline.');
    }
  }
  
  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('blacklisted_ips');
    
    // 2. CEK BLACKLIST
    const blocked = await blacklist.findOne({ ip: ip });
    if (blocked) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(ip, blocked.reason, blocked.toolInfo, blocked.piData));
    }
    
    // 3. DAPATKAN DATA PIAPI
    const piData = await getPiApiData(ip);
    
    // 4. DETEKSI PROXY/VPN
    const proxyVpnDetect = detectProxyVpn(piData);
    if (proxyVpnDetect) {
      await blacklist.insertOne({ 
        ip: ip, 
        reason: `proxy_vpn_detected_${proxyVpnDetect.toLowerCase()}`, 
        toolInfo: null,
        piData: piData,
        date: new Date(),
        userAgent: userAgent
      });
      
      await sendDiscordLog(ip, `Proxy/VPN Detected: ${proxyVpnDetect}`, userAgent, null, piData);
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(ip, `Menggunakan ${proxyVpnDetect}`, null, piData));
    }
    
    // 5. DETEKSI FORBIDDEN TOOLS
    const detectedTool = detectForbiddenTool(userAgent);
    
    if (detectedTool) {
      await blacklist.insertOne({ 
        ip: ip, 
        reason: `illegal_tool_${detectedTool.tool}`, 
        toolInfo: detectedTool,
        piData: piData,
        date: new Date(),
        userAgent: userAgent
      });
      
      await sendDiscordLog(ip, `Illegal Tool: ${detectedTool.tool}`, userAgent, detectedTool, piData);
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(ip, `Menggunakan ${detectedTool.tool.toUpperCase()}`, detectedTool, piData));
    }
    
    // 6. UNTUK BROWSER, TAMPILKAN KUIS
    if (req.method === 'POST') {
      await blacklist.insertOne({ 
        ip: ip, 
        reason: 'failed_quiz_skidder', 
        date: new Date(),
        piData: piData,
        userAgent: userAgent
      });
      
      await sendDiscordLog(ip, "Failed Security Quiz (Intentional Skidder)", userAgent, null, piData);
      
      return res.status(200).json({ status: 'blacklisted' });
    }
    
    // Tampilkan halaman kuis
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderQuizPage(ip));
    
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send('-- [pinathub-error]: internal server error.');
  } finally {
    await client.close();
  }
}
