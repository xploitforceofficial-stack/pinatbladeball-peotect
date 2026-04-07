import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// ============ BLACKLIST TOOLS SUPER LENGKAP ============
const BLACKLISTED_TOOLS = [
  'curl', 'wget', 'powershell', 'pwsh', 'vscode', 'insomnia', 'postman', 
  'python', 'python-requests', 'node-fetch', 'axios', 'go-http-client', 
  'bruno', 'httpie', 'rest-client', 'libcurl', 'wininet', 'java', 'okhttp',
  'apache-httpclient', 'requests', 'urllib3', 'httpx', 'fetch', 'xmlhttprequest',
  'nmap', 'masscan', 'zmap', 'gobuster', 'dirb', 'ffuf', 'hydra', 'sqlmap', 
  'burpsuite', 'metasploit', 'bash', 'zsh', 'terminal', 'xterm', 'termux',
  'node', 'nodejs', 'deno', 'bun', 'go', 'rust', 'ruby', 'perl', 'php',
  'npm', 'yarn', 'pip', 'gem', 'puppeteer', 'playwright', 'selenium', 'headless',
  'tor', 'proxychains', 'roblox/linux', 'roblox/windows', 'http-service',
  'crawler', 'scraper', 'bot', 'insomnia', 'postman', 'bruno'
];

function isBlacklistedTool(userAgent) {
  const uaLower = userAgent.toLowerCase();
  for (const tool of BLACKLISTED_TOOLS) {
    if (uaLower.includes(tool.toLowerCase())) {
      return tool;
    }
  }
  return false;
}

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

// Fungsi generate salted token
function generateSaltedToken() {
  const utcHour = Math.floor(Date.now() / 3600000);
  const rawString = utcHour + "PINAT_SALT_77";
  return Buffer.from(rawString).toString('base64');
}

function validateToken(token) {
  if (!token) return false;
  const expectedToken = generateSaltedToken();
  return token === expectedToken;
}

// Enhanced Discord logging
async function sendDiscordLog(ip, reason, ua, hwid = null, country = null, city = null, gameType = null) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Reason", value: `\`${reason}\``, inline: true },
    { name: "📱 User Agent", value: `\`${ua.substring(0, 100)}\`` },
    { name: "⏰ Timestamp", value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }) }
  ];

  if (hwid) fields.push({ name: "🔑 HWID", value: `\`${hwid}\``, inline: true });
  if (country && country !== 'Unknown') fields.push({ name: "🌍 Country", value: `\`${country}\``, inline: true });
  if (city && city !== 'Unknown') fields.push({ name: "🏙️ City", value: `\`${city}\``, inline: true });
  if (gameType) fields.push({ name: "🎮 Trap Game", value: `\`${gameType}\``, inline: true });

  const data = {
    username: "Pinat Guard System",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 Skidder Detected & Banned!",
      color: 15158332,
      fields: fields,
      footer: { text: "PinatHub Security Protection v4 - AntiTool + AntiVPN" }
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

// Fungsi untuk nampilin sambutan meriah buat yang udah di-ban (SAMA PERSIS KAYA ASLI)
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

// ============ 7 PERMAINAN (DENGAN UI YANG SAMA PERSIS) ============

function getRandomGame() {
  const games = [
    // Game 1: Tebak Angka
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">🎲</p>
          <p><strong>Tebak Angka 1-100</strong></p>
          <p>tebak angka yang dipikirkan sistem</p>
          <input type="number" id="guessInput" placeholder="masukkan angka..." style="width:80%; padding:10px; margin:10px 0; border:1px solid #eaeaea; border-radius:6px;">
          <button class="option" id="gameBtn" style="width:auto; display:inline-block;">tebak!</button>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          const target = Math.floor(Math.random() * 100) + 1;
          let attempts = 0;
          document.getElementById('gameBtn').onclick = () => {
            const guess = parseInt(document.getElementById('guessInput').value);
            attempts++;
            if(isNaN(guess)) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">isi angka dulu bre!</span>';
              return;
            }
            if(guess === target) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 bener! lanjut...</span>';
              setTimeout(() => next(), 1500);
            } else if(guess < target) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:orange;">📉 terlalu kecil, naikin!</span>';
            } else {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:orange;">📈 terlalu besar, turunin!</span>';
            }
            if(attempts >= 5) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">💀 gagal 5x, bye bye!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            }
          };
        </script>
      `,
      name: "Number Guessing Game"
    },
    // Game 2: Click Speed
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">⚡</p>
          <p><strong>Click Speed Test</strong></p>
          <p>klik tombol ini 10x secepat mungkin!</p>
          <button class="option" id="clickBtn" style="width:auto; display:inline-block; background:#000; color:#fff;">0/10</button>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          let clicks = 0;
          let startTime;
          const btn = document.getElementById('clickBtn');
          btn.onclick = () => {
            if(clicks === 0) startTime = Date.now();
            clicks++;
            btn.innerText = clicks + '/10';
            if(clicks === 10) {
              const time = (Date.now() - startTime) / 1000;
              if(time < 5) {
                document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">✅ ' + time + ' detik - kenceng juga! lanjut...</span>';
                setTimeout(() => next(), 1500);
              } else {
                document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">🐌 lemot amat ' + time + ' detik! banned!</span>';
                setTimeout(() => window.location.href = window.location.href, 2000);
              }
            }
          };
        </script>
      `,
      name: "Click Speed Test"
    },
    // Game 3: Teka-Teki
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">🧠</p>
          <p><strong>Teka-Teki Logika</strong></p>
          <p id="riddleQuestion"></p>
          <input type="text" id="riddleAnswer" placeholder="jawaban..." style="width:80%; padding:10px; margin:10px 0; border:1px solid #eaeaea; border-radius:6px;">
          <button class="option" id="gameBtn" style="width:auto; display:inline-block;">jawab!</button>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          const riddles = [
            { q: "Apa yang naik tapi gak pernah turun?", a: "umur", hint: "usia" },
            { q: "Semakin banyak diambil semakin besar, apa hayo?", a: "lubang", hint: "bolong" },
            { q: "Bisa terbang tanpa sayap, menangis tanpa mata?", a: "awan", hint: "langit" },
            { q: "Punya gigi tapi gak bisa makan?", a: "sisir", hint: "rambut" }
          ];
          const riddle = riddles[Math.floor(Math.random() * riddles.length)];
          document.getElementById('riddleQuestion').innerHTML = '<strong>' + riddle.q + '</strong>';
          let attempts = 0;
          document.getElementById('gameBtn').onclick = () => {
            const userAnswer = document.getElementById('riddleAnswer').value.toLowerCase().trim();
            attempts++;
            if(userAnswer === riddle.a) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 pinter! lanjut...</span>';
              setTimeout(() => next(), 1500);
            } else if(attempts >= 2) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">💀 hint: ' + riddle.hint + ' - gagal 2x, banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            } else {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:orange;">❌ salah! coba lagi...</span>';
            }
          };
        </script>
      `,
      name: "Logic Riddle"
    },
    // Game 4: Math Challenge
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">🧮</p>
          <p><strong>Math Challenge</strong></p>
          <p id="mathQuestion"></p>
          <input type="number" id="mathAnswer" placeholder="jawaban..." style="width:80%; padding:10px; margin:10px 0; border:1px solid #eaeaea; border-radius:6px;">
          <button class="option" id="gameBtn" style="width:auto; display:inline-block;">hitung!</button>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          const num1 = Math.floor(Math.random() * 50) + 10;
          const num2 = Math.floor(Math.random() * 50) + 10;
          const ops = ['+', '-', '*'];
          const op = ops[Math.floor(Math.random() * ops.length)];
          let result;
          if(op === '+') result = num1 + num2;
          else if(op === '-') result = num1 - num2;
          else result = num1 * num2;
          document.getElementById('mathQuestion').innerHTML = '<strong>' + num1 + ' ' + op + ' ' + num2 + ' = ?</strong>';
          let attempts = 0;
          document.getElementById('gameBtn').onclick = () => {
            const answer = parseInt(document.getElementById('mathAnswer').value);
            attempts++;
            if(answer === result) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 pinter matematika! lanjut...</span>';
              setTimeout(() => next(), 1500);
            } else if(attempts >= 3) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">💀 gagal 3x, banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            } else {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:orange;">❌ salah! coba lagi...</span>';
            }
          };
        </script>
      `,
      name: "Math Challenge"
    },
    // Game 5: Typing Speed
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">⌨️</p>
          <p><strong>Typing Speed Test</strong></p>
          <p>ketik ulang kata ini: <strong id="typeTarget" style="display:block; background:#f0f0f0; padding:10px; margin:10px; border-radius:6px;"></strong></p>
          <input type="text" id="typeInput" placeholder="ketik di sini..." style="width:80%; padding:10px; margin:10px 0; border:1px solid #eaeaea; border-radius:6px;">
          <button class="option" id="gameBtn" style="width:auto; display:inline-block;">submit!</button>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          const words = ['javascript', 'pinathub', 'skidder', 'security', 'roblox'];
          const target = words[Math.floor(Math.random() * words.length)];
          document.getElementById('typeTarget').innerText = target;
          let startTime = Date.now();
          document.getElementById('gameBtn').onclick = () => {
            const userInput = document.getElementById('typeInput').value.toLowerCase().trim();
            const time = (Date.now() - startTime) / 1000;
            if(userInput === target) {
              if(time < 10) {
                document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 ' + time + ' detik - cepet amat! lanjut...</span>';
                setTimeout(() => next(), 1500);
              } else {
                document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">🐌 ' + time + ' detik - pelan amat! banned!</span>';
                setTimeout(() => window.location.href = window.location.href, 2000);
              }
            } else {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">❌ salah ngetik! banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            }
          };
        </script>
      `,
      name: "Typing Speed Test"
    },
    // Game 6: Rock Paper Scissors
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">✊</p>
          <p><strong>Rock Paper Scissors</strong></p>
          <p>best of 3 - kalahkan AI!</p>
          <div style="display:flex; gap:10px; justify-content:center; margin:10px 0;">
            <button class="option" id="rock" style="width:auto;">✊ Batu</button>
            <button class="option" id="paper" style="width:auto;">✋ Kertas</button>
            <button class="option" id="scissors" style="width:auto;">✌️ Gunting</button>
          </div>
          <div id="rpsScore">Skor: Player 0 - 0 AI</div>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          let playerScore = 0, aiScore = 0;
          function playRPS(player) {
            const choices = ['rock', 'paper', 'scissors'];
            const ai = choices[Math.floor(Math.random() * 3)];
            let result = '';
            if(player === ai) result = 'draw';
            else if((player === 'rock' && ai === 'scissors') || (player === 'paper' && ai === 'rock') || (player === 'scissors' && ai === 'paper')) {
              result = 'win';
              playerScore++;
            } else {
              result = 'lose';
              aiScore++;
            }
            document.getElementById('rpsScore').innerText = 'Skor: Player ' + playerScore + ' - ' + aiScore + ' AI';
            if(playerScore === 2) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 menang! lanjut...</span>';
              setTimeout(() => next(), 1500);
            } else if(aiScore === 2) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">💀 kalah dari AI! banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            } else {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:orange;">' + result + '! lanjut game ' + (playerScore + aiScore + 1) + '/3</span>';
            }
          }
          document.getElementById('rock').onclick = () => playRPS('rock');
          document.getElementById('paper').onclick = () => playRPS('paper');
          document.getElementById('scissors').onclick = () => playRPS('scissors');
        </script>
      `,
      name: "Rock Paper Scissors"
    },
    // Game 7: Memory Match
    {
      html: `
        <div id="game-container" style="text-align:center;">
          <p style="font-size:24px; margin:10px 0;">🎴</p>
          <p><strong>Memory Match</strong></p>
          <p>cocokin pasangan emoji yang sama!</p>
          <div id="memoryGrid" style="display:grid; grid-template-columns:repeat(4,1fr); gap:8px; margin:15px 0;"></div>
          <div id="gameFeedback" style="margin-top:10px;"></div>
        </div>
        <script>
          const emojis = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊'];
          let cards = [...emojis, ...emojis];
          for(let i = cards.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [cards[i], cards[j]] = [cards[j], cards[i]];
          }
          let opened = [], matched = [], moves = 0;
          const grid = document.getElementById('memoryGrid');
          function render() {
            grid.innerHTML = cards.map((card, i) => 
              '<button class="option" style="font-size:20px; padding:10px; text-align:center;" onclick="flip(' + i + ')" ' + 
              (opened.includes(i) || matched.includes(i) ? 'disabled' : '') + '>' + 
              (opened.includes(i) || matched.includes(i) ? card : '❓') + '</button>'
            ).join('');
          }
          window.flip = (idx) => {
            if(opened.length === 2) return;
            opened.push(idx);
            moves++;
            if(opened.length === 2) {
              if(cards[opened[0]] === cards[opened[1]] && opened[0] !== opened[1]) {
                matched.push(...opened);
                opened = [];
                if(matched.length === cards.length) {
                  document.getElementById('gameFeedback').innerHTML = '<span style="color:green;">🎉 menang! lanjut...</span>';
                  setTimeout(() => next(), 1500);
                }
              } else {
                setTimeout(() => { opened = []; render(); }, 500);
              }
            }
            render();
            if(moves > 20) {
              document.getElementById('gameFeedback').innerHTML = '<span style="color:red;">💀 terlalu banyak gerakan! banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            }
          };
          render();
        </script>
      `,
      name: "Memory Match Game"
    }
  ];
  
  return games[Math.floor(Math.random() * games.length)];
}

export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const xForwardedFor = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const xHwid = req.headers['x-hwid'];
  const clientToken = req.headers['x-pinat-auth'];

  // DETEKSI TOOLS ILEGAL
  const detectedTool = isBlacklistedTool(userAgent);
  if (detectedTool) {
    try {
      await client.connect();
      const db = client.db('pinat_protection');
      const blacklist = db.collection('blacklisted_ips');
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: `blacklisted_tool: ${detectedTool}`, date: new Date() });
      const vpnCheck = await checkVpnProxy(xForwardedFor);
      await sendDiscordLog(xForwardedFor, `Blacklisted Tool: ${detectedTool}`, userAgent, xHwid, vpnCheck.country, vpnCheck.city);
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    } catch (err) {
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    }
  }

  // Region Lock (Indonesia Only)
  const countryCode = req.headers['x-vercel-ip-country'] || '';
  if (countryCode !== 'ID') {
    try {
      await client.connect();
      const db = client.db('pinat_protection');
      const blacklist = db.collection('blacklisted_ips');
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: `region_lock_${countryCode}`, date: new Date() });
      await sendDiscordLog(xForwardedFor, `Region Lock: ${countryCode} (bukan Indonesia)`, userAgent, xHwid);
    } catch (err) {}
    return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
  }

  // 1. DETEKSI ROBLOX (BYPASS SEMUA)
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');

  if (isRoblox) {
    try {
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-5');
      let content = await response.text();
      // Payload Obfuscation: Hex Encoding
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

    // A. Cek blacklist (IP atau HWID)
    const queryConditions = [{ ip: xForwardedFor }];
    if (xHwid) queryConditions.push({ hwid: xHwid });
    const blocked = await blacklist.findOne({ $or: queryConditions });
    if (blocked) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, blocked.hwid));
    }

    // B. Validasi Token (Salted Token Handshake)
    if (!validateToken(clientToken)) {
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: 'invalid_token_http_hook', date: new Date() });
      const vpnCheck = await checkVpnProxy(xForwardedFor);
      await sendDiscordLog(xForwardedFor, "Invalid Token (HTTP Hook Attempt)", userAgent, xHwid, vpnCheck.country, vpnCheck.city);
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // C. CEK VPN/PROXY/DATACENTER via ipapi.is
    const vpnCheck = await checkVpnProxy(xForwardedFor);
    if (vpnCheck.is_vpn || vpnCheck.is_proxy || vpnCheck.is_datacenter) {
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: 'vpn_proxy_detected', date: new Date() });
      await sendDiscordLog(xForwardedFor, "VPN/Proxy/DC Detected", userAgent, xHwid, vpnCheck.country, vpnCheck.city);
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // D. Langsung blacklist jika pakai tool terminal/ilegal
    if (isForbidden) {
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: 'illegal_tool_detected', date: new Date() });
      await sendDiscordLog(xForwardedFor, "Illegal Tool Detection", userAgent, xHwid, vpnCheck.country, vpnCheck.city);
      res.setHeader('Content-Type', 'text/html');
      return res.status(404).send(renderBlacklistPage(xForwardedFor, xHwid));
    }

    // E. Jika buka di browser, tampilkan UI Kuis (TAPI DENGAN GAME RANDOM)
    if (req.method === 'POST') {
      const gameName = req.headers['x-game-type'] || 'unknown';
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: `failed_game_trap_${gameName}`, date: new Date() });
      await sendDiscordLog(xForwardedFor, `Failed Game Trap (${gameName})`, userAgent, xHwid, vpnCheck.country, vpnCheck.city, gameName);
      return res.status(200).json({ status: 'blacklisted' });
    }

    // Pilih game RANDOM
    const selectedGame = getRandomGame();
    const gameHtml = selectedGame.html;
    const gameName = selectedGame.name;

    // Tampilkan Halaman Kuis (DENGAN UI YANG SAMA PERSIS, TAPI GAME NYA RANDOM)
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
                  <div class="step">security_check • ${gameName}</div>
                  <h1 id="q-text">verifikasi anti-skidder</h1>
                  <p id="q-sub">selesaikan permainan ini untuk verifikasi kamu bukan skidder.</p>
                  ${gameHtml}
              </div>

              <div id="log-stage" class="hidden">
                  <div class="step">reporting_incident • database_v4</div>
                  <h1>memproses laporan..</h1>
                  <p>jawaban kaka udah di-log. sistem lagi ngirim metadata ke owner buat di ban permanen.</p>
                  <div class="terminal" id="term"></div>
                  <button class="option" style="margin-top:20px; text-align:center;" onclick="location.reload()">tutup</button>
              </div>
          </div>

          <script>
              window.next = async function() {
                  await fetch(window.location.href, { 
                      method: 'POST',
                      headers: { 'X-Game-Type': '${gameName}' }
                  });
                  document.getElementById('q-stage').classList.add('hidden');
                  document.getElementById('log-stage').classList.remove('hidden');
                  const term = document.getElementById('term');
                  term.style.display = 'block';
                  const logs = [
                      "> target_ip: ${xForwardedFor}",
                      "> game_trap: ${gameName}",
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
              };
          </script>
      </body>
      </html>
    `);

  } catch (err) {
    console.error(err);
    return res.status(500).send('-- [pinathub-error]: internal server error.');
  }
}
