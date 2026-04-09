import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// Konfigurasi PIApi
const PIAPI_KEY = "c5473140651f84c8d9ba";
const PIAPI_BASE_URL = "https://piapi.org/api";

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
  'scrapy', 'beautifulsoup', 'crawler', 'spider', 'bot',
  'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'facebot',
  'ia_archiver', 'baiduspider', 'yandexbot', 'seznambot',
  
  // Additional Suspicious
  'perl', 'lwp', 'lua', 'socket.http', 'telnet', 'netcat',
  'socat', 'ncat', 'openssl', 'gnutls', 'libcurl'
];

// Fungsi untuk mendeteksi forbidden tools dengan prioritas tinggi
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

// UPDATE: Kirim log ke Discord Webhook dengan data PIApi
async function sendDiscordLog(ip, reason, ua, toolInfo = null, piData = null) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Violation", value: `\`${reason}\``, inline: true },
    { name: "🔧 Tool/UA", value: `\`${ua.substring(0, 100)}\``, inline: false }
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
    fields.push(
      { name: "📍 Location", value: `${piData.location?.city}, ${piData.location?.country_code || 'Unknown'}`, inline: true },
      { name: "🏢 ISP/Company", value: piData.company?.name || piData.asn?.org || "Unknown", inline: true },
      { name: "⚠️ Risk Factors", value: `Datacenter: ${piData.is_datacenter ? 'Yes' : 'No'}\nProxy: ${piData.is_proxy ? 'Yes' : 'No'}\nVPN: ${piData.is_vpn ? 'Yes' : 'No'}`, inline: true }
    );
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

// Halaman Blacklist dengan efek terminal
function renderBlacklistPage(ip, reason, toolDetected = null) {
  const toolMessage = toolDetected ? `🔧 Tool terdeteksi: ${toolDetected.tool.toUpperCase()}` : '';
  
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>🔒 ACCESS DENIED - PERMANENT BAN</title>
        <style>
            body {
                background: #0a0a0a;
                color: #00ff00;
                font-family: 'Courier New', monospace;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
                text-align: center;
            }
            .content {
                max-width: 700px;
                padding: 40px;
                background: #0a0a0a;
                border: 2px solid #ff0000;
                border-radius: 10px;
                box-shadow: 0 0 20px rgba(255,0,0,0.3);
            }
            h1 {
                font-size: 64px;
                font-weight: 900;
                margin: 0;
                color: #ff0000;
                text-shadow: 0 0 10px rgba(255,0,0,0.5);
                animation: blink 1s infinite;
            }
            @keyframes blink {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .badge {
                background: #ff0000;
                color: #fff;
                padding: 5px 15px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: bold;
                text-transform: uppercase;
                display: inline-block;
                margin-bottom: 20px;
            }
            .terminal {
                background: #000;
                padding: 15px;
                border-radius: 5px;
                text-align: left;
                font-size: 12px;
                margin-top: 20px;
                border-left: 3px solid #00ff00;
            }
            .blink {
                animation: blink 1s infinite;
            }
            hr {
                border-color: #ff0000;
                margin: 20px 0;
            }
        </style>
    </head>
    <body>
        <div class="content">
            <div class="badge">⚠️ PERMANENT BAN ⚠️</div>
            <h1>ACCESS DENIED</h1>
            <h2 style="color: #ff4444;">Yah, kena mental ya? 😊</h2>
            <p>IP <strong>${ip}</strong> telah resmi ditandai sebagai <strong style="color: #ff0000;">SKIDDER PROFESSIONAL</strong></p>
            <p>${toolMessage}</p>
            <div class="terminal">
                > status: blacklisted<br>
                > reason: ${reason}<br>
                > ban_type: permanent<br>
                > appeal: not available<br>
                > learn_mtk: recommended<br>
                > ${new Date().toLocaleString('id-ID')}
            </div>
            <hr>
            <p style="font-size: 11px; color: #666;">
                incident_id: ${Math.random().toString(36).substring(2, 10)}<br>
                This IP has been reported to security systems
            </p>
        </div>
    </body>
    </html>
  `;
}

// MAIN HANDLER
export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const ip = getRealIP(req);
  
  // 1. DETEKSI ROBLOX (BYPASS)
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');
  
  if (isRoblox) {
    try {
      const response = await fetch('https://pinatbladeball-peotect.vercel.app/api/script.js');
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
      return res.status(403).send(renderBlacklistPage(ip, blocked.reason, blocked.toolInfo));
    }
    
    // 3. DETEKSI FORBIDDEN TOOLS (PRIORITAS TINGGI)
    const detectedTool = detectForbiddenTool(userAgent);
    
    if (detectedTool) {
      // Dapatkan data dari PIApi
      const piData = await getPiApiData(ip);
      
      // Simpan ke database
      await blacklist.insertOne({ 
        ip: ip, 
        reason: `illegal_tool_${detectedTool.tool}`, 
        toolInfo: detectedTool,
        piData: piData,
        date: new Date(),
        userAgent: userAgent
      });
      
      // Kirim log ke Discord
      await sendDiscordLog(ip, `Illegal Tool: ${detectedTool.tool} (${detectedTool.priority} priority)`, userAgent, detectedTool, piData);
      
      // Tampilkan halaman blacklist
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(ip, `Menggunakan ${detectedTool.tool.toUpperCase()}`, detectedTool));
    }
    
    // 4. UNTUK BROWSER, TAMPILKAN KUIS
    if (req.method === 'POST') {
      // Dapatkan data PIApi untuk logging
      const piData = await getPiApiData(ip);
      
      await blacklist.insertOne({ 
        ip: ip, 
        reason: 'failed_quiz_skidder', 
        date: new Date(),
        piData: piData
      });
      
      await sendDiscordLog(ip, "Failed Security Quiz (Intentional Skidder)", userAgent, null, piData);
      
      return res.status(200).json({ status: 'blacklisted' });
    }
    
    // Tampilkan halaman kuis
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="UTF-8">
          <title>Security Verification</title>
          <style>
              body {
                  background: #fff;
                  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                  display: flex;
                  justify-content: center;
                  align-items: center;
                  min-height: 100vh;
                  margin: 0;
                  padding: 20px;
              }
              .container {
                  max-width: 500px;
                  width: 100%;
                  padding: 30px;
                  border: 1px solid #eaeaea;
                  border-radius: 12px;
                  box-shadow: 0 4px 12px rgba(0,0,0,0.05);
              }
              .step {
                  font-size: 12px;
                  color: #666;
                  margin-bottom: 10px;
                  text-transform: uppercase;
                  letter-spacing: 1px;
              }
              h2 {
                  font-size: 24px;
                  margin: 0 0 10px 0;
              }
              .option {
                  width: 100%;
                  padding: 12px;
                  margin: 8px 0;
                  border: 1px solid #eaeaea;
                  border-radius: 8px;
                  background: #fff;
                  text-align: left;
                  cursor: pointer;
                  transition: all 0.2s;
              }
              .option:hover {
                  border-color: #000;
                  background: #fafafa;
              }
              .hidden {
                  display: none;
              }
              .terminal-log {
                  background: #000;
                  color: #0f0;
                  padding: 15px;
                  border-radius: 8px;
                  font-family: monospace;
                  font-size: 11px;
                  margin-top: 20px;
              }
          </style>
      </head>
      <body>
          <div class="container">
              <div id="quiz">
                  <div class="step">VERIFICATION • STEP <span id="step">1</span>/3</div>
                  <h2 id="question">Deteksi akses ilegal...</h2>
                  <p id="subtext">Kami mendeteksi Anda menggunakan browser. Verifikasi bahwa Anda bukan skidder.</p>
                  <div id="options"></div>
              </div>
              <div id="result" class="hidden">
                  <div class="step">REPORTING...</div>
                  <h2>Memproses laporan</h2>
                  <p>Jawaban telah dicatat. Sistem sedang mengirim data ke owner.</p>
                  <div class="terminal-log" id="terminal"></div>
                  <button class="option" onclick="location.reload()" style="text-align: center; margin-top: 15px;">Tutup</button>
              </div>
          </div>
          
          <script>
              let step = 1;
              const questions = [
                  { text: "Siapa idola para skidder?", sub: "Pilih jawaban yang paling tepat:" },
                  { text: "Apa cita-cita kaka?", sub: "Jujur ya :)" }
              ];
              
              const optionsList = [
                  ['Bang Rafael (pencipta skid)', 'Pencuri script random di YouTube', 'Coder yang gabut', 'Anak TI yang nyasar'],
                  ['Jadi tukang copas profesional', 'Pensiun trus belajar MTK', 'Jualan script abal-abal', 'Nginjekin karya orang']
              ];
              
              function renderOptions() {
                  const optsDiv = document.getElementById('options');
                  const idx = step - 1;
                  optsDiv.innerHTML = '';
                  optionsList[idx].forEach(opt => {
                      const btn = document.createElement('button');
                      btn.className = 'option';
                      btn.textContent = opt;
                      btn.onclick = () => next();
                      optsDiv.appendChild(btn);
                  });
              }
              
              function next() {
                  if (step < 3) {
                      step++;
                      document.getElementById('step').innerText = step;
                      if (step <= 2) {
                          document.getElementById('question').innerText = questions[step-2].text;
                          document.getElementById('subtext').innerText = questions[step-2].sub;
                          renderOptions();
                      } else {
                          finish();
                      }
                  } else {
                      finish();
                  }
              }
              
              async function finish() {
                  await fetch(window.location.href, { method: 'POST' });
                  
                  document.getElementById('quiz').classList.add('hidden');
                  document.getElementById('result').classList.remove('hidden');
                  
                  const term = document.getElementById('terminal');
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
                      term.innerHTML += logs[i] + "<br>";
                      i++;
                      if (i >= logs.length) clearInterval(interval);
                  }, 500);
              }
              
              // Initial render
              document.getElementById('question').innerText = questions[0].text;
              document.getElementById('subtext').innerText = questions[0].sub;
              renderOptions();
          </script>
      </body>
      </html>
    `);
    
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send('-- [pinathub-error]: internal server error.');
  } finally {
    await client.close();
  }
}
