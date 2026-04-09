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

// DAFTAR BLACKLIST TOOLS
const FORBIDDEN_TOOLS = [
  'powershell', 'pwsh', 'powershell-core', 'cmd', 'command prompt',
  'terminal', 'termux', 'bash', 'zsh', 'sh', 'ksh', 'fish', 'dash',
  'xterm', 'konsole', 'gnome-terminal', 'alacritty', 'kitty',
  'curl', 'wget', 'fetch', 'httpie', 'xh', 'hurl', 'restclient',
  'postman', 'insomnia', 'bruno', 'hoppscotch', 'paw', 'rested',
  'python', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'http.client',
  'node-fetch', 'axios', 'superagent', 'got', 'request', 'undici',
  'php', 'curl.php', 'java', 'okhttp', 'apache-httpclient',
  'ruby', 'net-http', 'faraday', 'go-http-client', 'rust-reqwest',
  'selenium', 'puppeteer', 'playwright', 'cypress', 'webdriver',
  'headless', 'phantomjs', 'casperjs', 'zombie.js', 'nightmare',
  'nmap', 'masscan', 'zmap', 'hydra', 'medusa', 'ncrack',
  'sqlmap', 'burpsuite', 'owasp', 'zap', 'nikto', 'wpscan',
  'dirb', 'gobuster', 'ffuf', 'wfuzz', 'dirbuster',
  'aria2', 'axel', 'wget2', 'lwp-request', 'gdown', 'youtube-dl',
  'yt-dlp', 'ffmpeg', 'rtmpdump', 'streamlink',
  'ab', 'siege', 'wrk', 'vegeta', 'hey', 'boom', 'jmeter',
  'gatling', 'locust', 'k6', 'artillery', 'tsung',
  'scrapy', 'beautifulsoup', 'crawler', 'spider', 'bot'
];

function detectForbiddenTool(userAgent) {
  const ua = userAgent.toLowerCase();
  const highPriority = ['powershell', 'pwsh', 'terminal', 'termux', 'cmd', 'bash', 'zsh'];
  
  for (const tool of highPriority) {
    if (ua.includes(tool)) {
      return { tool, priority: 'HIGH', type: 'terminal/shell' };
    }
  }
  
  for (const tool of FORBIDDEN_TOOLS) {
    if (ua.includes(tool)) {
      return { tool, priority: 'NORMAL', type: 'other' };
    }
  }
  return null;
}

function getRealIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  const realIP = req.headers['x-real-ip'];
  const cfIP = req.headers['cf-connecting-ip'];
  const trueIP = req.headers['true-client-ip'];
  
  let ip = forwarded?.split(',')[0] || realIP || cfIP || trueIP || req.socket.remoteAddress;
  
  if (ip && ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  }
  return ip;
}

async function sendDiscordLog(ip, reason, ua, toolInfo = null, piData = null, additionalInfo = {}) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Violation", value: `\`${reason}\``, inline: true },
    { name: "🔧 User Agent", value: `\`${ua.substring(0, 100)}\``, inline: false }
  ];
  
  if (toolInfo) {
    fields.push({ 
      name: "⚠️ Detected Tool", 
      value: `\`${toolInfo.tool}\` (${toolInfo.priority} priority)`, 
      inline: true 
    });
  }
  
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
      footer: { text: "PinatHub Security Protection v6 | Game Edition" },
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
function renderBlacklistPage(ip, reason, toolDetected = null, piData = null, gameScore = null) {
  const toolMessage = toolDetected ? `🔧 Tool terdeteksi: ${toolDetected.tool.toUpperCase()}` : '';
  const proxyMessage = piData && detectProxyVpn(piData) ? `🚫 ${detectProxyVpn(piData)} DETECTED` : '';
  const scoreMessage = gameScore ? `🎮 Game Score: ${gameScore}` : '';
  
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
                
                ${toolMessage || proxyMessage || scoreMessage ? `
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
                    ${scoreMessage ? `
                    <div class="info-item">
                        <div class="info-label">Game Score</div>
                        <div class="info-value">${gameScore}</div>
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

// Halaman Game untuk Whitelist (Bisa main game tanpa takut kena ban)
function renderWhitelistGamePage(ip) {
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Owner's Playground - PinatHub</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-success: #0070f3; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; margin: 0; padding: 40px 20px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 40px; }
            .badge-owner { display: inline-block; background: linear-gradient(135deg, #0070f3, #00c6ff); color: white; font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 100px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; }
            h1 { font-size: 48px; font-weight: 700; letter-spacing: -2px; margin-bottom: 8px; }
            .sub { color: var(--accents-3); font-size: 14px; }
            .games-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 24px; margin-bottom: 40px; }
            .game-card { border: 1px solid var(--accents-2); border-radius: 12px; padding: 24px; background: var(--geist-background); transition: transform 0.2s, box-shadow 0.2s; }
            .game-card:hover { transform: translateY(-4px); box-shadow: 0 12px 40px rgba(0,0,0,0.1); }
            .game-icon { font-size: 48px; margin-bottom: 16px; }
            .game-title { font-size: 20px; font-weight: 600; margin-bottom: 8px; }
            .game-desc { color: var(--accents-3); font-size: 13px; margin-bottom: 20px; line-height: 1.5; }
            .play-btn { background: var(--geist-foreground); color: var(--geist-background); border: none; padding: 10px 20px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: opacity 0.2s; }
            .play-btn:hover { opacity: 0.8; }
            .game-area { border: 1px solid var(--accents-2); border-radius: 12px; padding: 32px; margin-top: 20px; background: var(--accents-1); }
            .game-status { font-size: 14px; color: var(--accents-3); margin-bottom: 20px; }
            .option-btn { background: var(--geist-background); border: 1px solid var(--accents-2); padding: 12px 20px; border-radius: 8px; margin: 5px; cursor: pointer; transition: all 0.2s; font-size: 14px; }
            .option-btn:hover { border-color: var(--geist-foreground); transform: translateY(-1px); }
            .input-box { padding: 12px; border: 1px solid var(--accents-2); border-radius: 8px; font-size: 14px; width: 200px; margin-right: 10px; }
            .score { font-size: 24px; font-weight: 600; margin-top: 20px; }
            .ip-info { background: #000; color: #0f0; padding: 12px; border-radius: 8px; font-family: monospace; font-size: 12px; margin-top: 20px; text-align: center; }
            hr { border: none; border-top: 1px solid var(--accents-2); margin: 20px 0; }
            .footer { text-align: center; font-size: 11px; color: var(--accents-3); margin-top: 40px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="badge-owner">👑 OWNER ACCESS • WHITELISTED</div>
                <h1>🎮 Owner's Playground</h1>
                <div class="sub">IP: ${ip} • Selamat bermain! Tidak akan kena blacklist.</div>
            </div>

            <div class="games-grid">
                <div class="game-card">
                    <div class="game-icon">🔢</div>
                    <div class="game-title">Tebak Angka</div>
                    <div class="game-desc">Tebak angka antara 1-100. Skidder akan langsung kena ban kalau salah! Tapi kamu aman~</div>
                    <button class="play-btn" onclick="showGame('guess')">Mainkan</button>
                </div>
                <div class="game-card">
                    <div class="game-icon">🚪</div>
                    <div class="game-title">Pilih Pintu</div>
                    <div class="game-desc">Pilih pintu yang benar. Kalau skidder salah pilih, langsung banned! Kamu bisa coba sepuasnya.</div>
                    <button class="play-btn" onclick="showGame('door')">Mainkan</button>
                </div>
                <div class="game-card">
                    <div class="game-icon">⌨️</div>
                    <div class="game-title">Typing Test</div>
                    <div class="game-desc">Ketik kalimat dengan cepat. Skidder yang gagal akan di-ban permanen.</div>
                    <button class="play-btn" onclick="showGame('typing')">Mainkan</button>
                </div>
            </div>

            <div id="gameArea" class="game-area" style="display: none;">
                <div id="gameContent"></div>
            </div>

            <div class="ip-info">
                🛡️ WHITELISTED PROTECTION ACTIVE • Semua game aman dimainkan
            </div>
            <hr>
            <div class="footer">
                PinatHub Security v6 • Whitelist Mode • Games for Owner
            </div>
        </div>

        <script>
            let currentGame = null;
            let guessNumber = null;
            let guessAttempts = 0;
            let doorChoice = null;
            let typingText = "";
            let typingStartTime = null;

            function showGame(game) {
                currentGame = game;
                const gameArea = document.getElementById('gameArea');
                const gameContent = document.getElementById('gameContent');
                gameArea.style.display = 'block';
                
                if (game === 'guess') {
                    guessNumber = Math.floor(Math.random() * 100) + 1;
                    guessAttempts = 0;
                    gameContent.innerHTML = \`
                        <div class="game-status">🎯 GAME: TEBAK ANGKA (1-100)</div>
                        <div>Tebak angka yang saya pikirkan:</div>
                        <input type="number" id="guessInput" class="input-box" placeholder="Masukkan angka">
                        <button class="option-btn" onclick="makeGuess()">Tebak!</button>
                        <div id="guessResult" style="margin-top: 15px;"></div>
                        <div class="score">Percobaan: \${guessAttempts}</div>
                    \`;
                } else if (game === 'door') {
                    doorChoice = Math.floor(Math.random() * 3);
                    gameContent.innerHTML = \`
                        <div class="game-status">🚪 GAME: PILIH PINTU</div>
                        <div>Di belakang salah satu pintu ini ada harta karun! Pilih dengan bijak:</div>
                        <div style="margin-top: 20px;">
                            <button class="option-btn" onclick="chooseDoor(0)">🚪 PINTU 1</button>
                            <button class="option-btn" onclick="chooseDoor(1)">🚪 PINTU 2</button>
                            <button class="option-btn" onclick="chooseDoor(2)">🚪 PINTU 3</button>
                        </div>
                        <div id="doorResult" style="margin-top: 15px;"></div>
                    \`;
                } else if (game === 'typing') {
                    const words = ["pinathub", "javascript", "vercel", "security", "protection", "skidder", "terminal", "blacklist"];
                    typingText = words[Math.floor(Math.random() * words.length)];
                    gameContent.innerHTML = \`
                        <div class="game-status">⌨️ GAME: TYPING TEST</div>
                        <div style="background: #000; color: #0f0; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 18px; margin-bottom: 20px;">\${typingText}</div>
                        <div>Ketik kata di atas:</div>
                        <input type="text" id="typingInput" class="input-box" placeholder="Ketik di sini..." oninput="checkTyping()">
                        <div id="typingResult" style="margin-top: 15px;"></div>
                    \`;
                    typingStartTime = Date.now();
                }
            }

            function makeGuess() {
                const input = document.getElementById('guessInput');
                const guess = parseInt(input.value);
                const resultDiv = document.getElementById('guessResult');
                const scoreDiv = document.querySelector('.score');
                
                if (isNaN(guess)) {
                    resultDiv.innerHTML = '❌ Masukkan angka yang valid!';
                    return;
                }
                
                guessAttempts++;
                scoreDiv.innerHTML = \`Percobaan: \${guessAttempts}\`;
                
                if (guess === guessNumber) {
                    resultDiv.innerHTML = \`✅ BENAR! Angkanya adalah \${guessNumber}. Kamu menang dalam \${guessAttempts} percobaan! 🎉\`;
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => showGame('guess'), 2000);
                } else if (guess < guessNumber) {
                    resultDiv.innerHTML = '📈 Terlalu kecil! Coba lagi.';
                } else {
                    resultDiv.innerHTML = '📉 Terlalu besar! Coba lagi.';
                }
                input.value = '';
            }

            function chooseDoor(door) {
                const resultDiv = document.getElementById('doorResult');
                if (door === doorChoice) {
                    resultDiv.innerHTML = '🎉 SELAMAT! Kamu menemukan harta karun! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => showGame('door'), 2000);
                } else {
                    resultDiv.innerHTML = '💀 Pintu kosong... Coba lagi! (Skidder bakal kena ban kalau begini)';
                    resultDiv.style.color = '#ff0000';
                    setTimeout(() => showGame('door'), 1500);
                }
            }

            function checkTyping() {
                const input = document.getElementById('typingInput');
                const resultDiv = document.getElementById('typingResult');
                
                if (input.value === typingText) {
                    const timeTaken = ((Date.now() - typingStartTime) / 1000).toFixed(2);
                    resultDiv.innerHTML = \`✅ PERFECT! Waktu: \${timeTaken} detik. Kamu hebat! 🎉\`;
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => showGame('typing'), 2000);
                }
            }
        </script>
    </body>
    </html>
  `;
}

// Halaman Game untuk Skidder (Sebelum kena ban)
function renderSkidderGamePage(ip) {
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Required - PinatHub</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-error: #ff0000; --geist-success: #0070f3; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
            .container { max-width: 600px; width: 100%; }
            .card { border: 1px solid var(--accents-2); border-radius: 12px; padding: 40px 32px; background: var(--geist-background); box-shadow: 0 8px 30px rgba(0,0,0,0.05); }
            .warning-badge { display: inline-block; background: var(--geist-error); color: white; font-size: 11px; font-weight: 600; padding: 4px 12px; border-radius: 100px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; }
            .step { font-size: 12px; color: var(--accents-3); margin-bottom: 16px; text-transform: uppercase; letter-spacing: 1px; }
            h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em; }
            .subtext { color: var(--accents-3); font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
            .option { width: 100%; padding: 12px 16px; margin-bottom: 8px; background: var(--geist-background); border: 1px solid var(--accents-2); border-radius: 8px; font-size: 14px; text-align: left; cursor: pointer; transition: all 0.2s ease; font-family: inherit; }
            .option:hover { border-color: var(--geist-foreground); background: var(--accents-1); transform: translateY(-1px); }
            .game-area { margin: 20px 0; }
            .input-box { padding: 12px; border: 1px solid var(--accents-2); border-radius: 8px; font-size: 14px; width: 100%; margin-bottom: 12px; }
            .terminal { background: #000; color: #0f0; padding: 16px; border-radius: 8px; font-family: monospace; font-size: 11px; margin-top: 24px; line-height: 1.5; display: none; }
            .hidden { display: none; }
            .vercel-icon { margin-bottom: 24px; }
            hr { border: none; border-top: 1px solid var(--accents-2); margin: 24px 0 16px; }
            .footer-text { font-size: 11px; color: var(--accents-3); text-align: center; margin-top: 20px; }
            .score { font-size: 13px; color: var(--accents-3); margin-top: 10px; }
            .danger-text { color: var(--geist-error); font-size: 12px; margin-top: 10px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="vercel-icon">
                    <svg width="25" height="22" viewBox="0 0 76 65" fill="currentColor"><path d="M37.5274 0L75.0548 65H0L37.5274 0Z"/></svg>
                </div>
                
                <div class="warning-badge">⚠️ PERINGATAN</div>
                
                <div id="game-stage">
                    <div class="step">SECURITY CHALLENGE • GAME <span id="game-num">1</span>/3</div>
                    <h1 id="game-title">Selamat datang, Skidder!</h1>
                    <div class="subtext" id="game-desc">Kamu punya kesempatan untuk membuktikan bahwa kamu BUKAN skidder. Pilih game di bawah ini dan menangkan!</div>
                    
                    <div class="game-area">
                        <button class="option" onclick="startGame('guess')">🔢 TEBAK ANGKA (1-100)</button>
                        <button class="option" onclick="startGame('door')">🚪 PILIH PINTU (1/3 kesempatan)</button>
                        <button class="option" onclick="startGame('typing')">⌨️ TYPING TEST (Ketik kata)</button>
                    </div>
                    
                    <div id="active-game" style="display: none;">
                        <hr>
                        <div id="game-content"></div>
                        <div class="danger-text" id="danger-warning"></div>
                    </div>
                </div>

                <div id="log-stage" class="hidden">
                    <div class="step">REPORTING INCIDENT</div>
                    <h1>GAME OVER - SKIDDER CONFIRMED</h1>
                    <div class="subtext">Kamu gagal dalam tantangan. Sistem akan mengirim metadata ke owner untuk ban permanen.</div>
                    <div class="terminal" id="terminal-log"></div>
                    <hr>
                    <button class="option" onclick="location.reload()" style="text-align: center; margin-top: 16px;">Tutup</button>
                </div>
                
                <div class="footer-text">
                    protected by pinathub security • 3 chances before permanent ban
                </div>
            </div>
        </div>

        <script>
            let currentGame = null;
            let guessNumber = null;
            let guessAttempts = 0;
            let doorChoice = null;
            let gameFailed = false;
            let currentGameType = null;
            
            function startGame(gameType) {
                if (gameFailed) return;
                currentGameType = gameType;
                const activeGameDiv = document.getElementById('active-game');
                const gameContent = document.getElementById('game-content');
                const gameStage = document.getElementById('game-stage');
                
                activeGameDiv.style.display = 'block';
                
                if (gameType === 'guess') {
                    guessNumber = Math.floor(Math.random() * 100) + 1;
                    guessAttempts = 0;
                    gameContent.innerHTML = \`
                        <div><strong>🔢 TEBAK ANGKA (1-100)</strong></div>
                        <div style="margin: 15px 0;">Tebak angka yang saya pikirkan. Kamu punya 5 percobaan!</div>
                        <input type="number" id="guessInput" class="input-box" placeholder="Masukkan angka (1-100)">
                        <button class="option" onclick="makeGuess()" style="text-align: center;">Tebak!</button>
                        <div id="guessResult" style="margin-top: 15px;"></div>
                        <div class="score">Percobaan: \${guessAttempts}/5</div>
                    \`;
                    document.getElementById('danger-warning').innerHTML = '⚠️ Jika gagal, IP kamu akan di-BAN PERMANEN!';
                } else if (gameType === 'door') {
                    doorChoice = Math.floor(Math.random() * 3);
                    gameContent.innerHTML = \`
                        <div><strong>🚪 PILIH PINTU</strong></div>
                        <div style="margin: 15px 0;">Hanya 1 pintu yang benar. Pilih dengan bijak!</div>
                        <div>
                            <button class="option" onclick="chooseDoor(0)" style="text-align: center;">🚪 PINTU 1</button>
                            <button class="option" onclick="chooseDoor(1)" style="text-align: center;">🚪 PINTU 2</button>
                            <button class="option" onclick="chooseDoor(2)" style="text-align: center;">🚪 PINTU 3</button>
                        </div>
                        <div id="doorResult" style="margin-top: 15px;"></div>
                    \`;
                    document.getElementById('danger-warning').innerHTML = '⚠️ Pilih salah = BAN PERMANEN!';
                } else if (gameType === 'typing') {
                    const words = ["pinathub", "javascript", "vercel", "security"];
                    const randomWord = words[Math.floor(Math.random() * words.length)];
                    gameContent.innerHTML = \`
                        <div><strong>⌨️ TYPING TEST</strong></div>
                        <div style="background: #000; color: #0f0; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 18px; margin: 15px 0;">\${randomWord}</div>
                        <div>Ketik kata di atas dengan tepat:</div>
                        <input type="text" id="typingInput" class="input-box" placeholder="Ketik di sini...">
                        <button class="option" onclick="checkTyping()" style="text-align: center;">Submit</button>
                        <div id="typingResult" style="margin-top: 15px;"></div>
                    \`;
                    window.currentTypingWord = randomWord;
                    document.getElementById('danger-warning').innerHTML = '⚠️ Salah ketik = BAN PERMANEN!';
                }
            }
            
            function makeGuess() {
                if (gameFailed) return;
                const input = document.getElementById('guessInput');
                const guess = parseInt(input.value);
                const resultDiv = document.getElementById('guessResult');
                const scoreDiv = document.querySelector('.score');
                
                if (isNaN(guess)) {
                    resultDiv.innerHTML = '❌ Masukkan angka yang valid!';
                    return;
                }
                
                guessAttempts++;
                scoreDiv.innerHTML = \`Percobaan: \${guessAttempts}/5\`;
                
                if (guess === guessNumber) {
                    resultDiv.innerHTML = '✅ SELAMAT! Kamu bukan skidder. Akses GRANTED! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => window.location.reload(), 2000);
                } else if (guessAttempts >= 5) {
                    gameFailed = true;
                    resultDiv.innerHTML = '💀 GAME OVER! Kamu gagal...';
                    finishGame(false);
                } else if (guess < guessNumber) {
                    resultDiv.innerHTML = '📈 Terlalu kecil! Coba lagi.';
                } else {
                    resultDiv.innerHTML = '📉 Terlalu besar! Coba lagi.';
                }
                input.value = '';
            }
            
            function chooseDoor(door) {
                if (gameFailed) return;
                const resultDiv = document.getElementById('doorResult');
                if (door === doorChoice) {
                    resultDiv.innerHTML = '🎉 SELAMAT! Kamu bukan skidder. Akses GRANTED! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => window.location.reload(), 2000);
                } else {
                    gameFailed = true;
                    resultDiv.innerHTML = '💀 GAME OVER! Pintu salah...';
                    finishGame(false);
                }
            }
            
            function checkTyping() {
                if (gameFailed) return;
                const input = document.getElementById('typingInput');
                const resultDiv = document.getElementById('typingResult');
                
                if (input.value === window.currentTypingWord) {
                    resultDiv.innerHTML = '✅ SELAMAT! Kamu bukan skidder. Akses GRANTED! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => window.location.reload(), 2000);
                } else {
                    gameFailed = true;
                    resultDiv.innerHTML = '💀 GAME OVER! Typing mismatch...';
                    finishGame(false);
                }
            }
            
            async function finishGame(isWin) {
                if (isWin) {
                    return;
                }
                
                await fetch(window.location.href, { method: 'POST', body: JSON.stringify({ gameResult: 'failed' }) });
                
                document.getElementById('game-stage').classList.add('hidden');
                document.getElementById('log-stage').classList.remove('hidden');
                
                const terminal = document.getElementById('terminal-log');
                terminal.style.display = 'block';
                
                const logs = [
                    "> target_ip: ${ip}",
                    "> game_status: failed",
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
    console.log(`[WHITELIST] IP ${ip} diizinkan akses penuh - Mode Game`);
    
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
    
    // Tampilkan halaman game untuk whitelist (bisa main game tanpa takut kena ban)
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderWhitelistGamePage(ip));
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
      return res.status(403).send(renderBlacklistPage(ip, blocked.reason, blocked.toolInfo, blocked.piData, blocked.gameScore));
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
    
    // 6. UNTUK BROWSER, TAMPILKAN GAME (Skidder bisa bermain sebelum kena ban)
    if (req.method === 'POST') {
      const body = req.body ? JSON.parse(req.body) : {};
      
      await blacklist.insertOne({ 
        ip: ip, 
        reason: 'failed_game_skidder', 
        date: new Date(),
        piData: piData,
        userAgent: userAgent,
        gameScore: body.gameResult === 'failed' ? 0 : 50
      });
      
      await sendDiscordLog(ip, "Failed Security Game (Skidder Confirmed)", userAgent, null, piData, { extra: "Failed all 3 game challenges" });
      
      return res.status(200).json({ status: 'blacklisted' });
    }
    
    // Tampilkan halaman game untuk skidder
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderSkidderGamePage(ip));
    
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send('-- [pinathub-error]: internal server error.');
  } finally {
    await client.close();
  }
}
