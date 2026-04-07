import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// ============ BLACKLIST TOOLS SUPER LENGKAP (TANPA ROBLOX EXECUTORS) ============
const BLACKLISTED_TOOLS = [
  // HTTP Clients / Tools
  'curl', 'wget', 'powershell', 'pwsh', 'vscode', 'insomnia', 'postman', 
  'python', 'python-requests', 'node-fetch', 'axios', 'go-http-client', 
  'bruno', 'httpie', 'rest-client', 'libcurl', 'wininet', 'java', 'okhttp',
  'apache-httpclient', 'requests', 'urllib3', 'httpx', 'fetch', 'xmlhttprequest',
  'httrack', 'wget2', 'aria2', 'rustup', 'cargo', 'ruby', 'perl', 'php',
  
  // Network / Scanner Tools
  'nmap', 'masscan', 'zmap', 'gobuster', 'dirb', 'ffuf', 'hydra', 'medusa',
  'nikto', 'wapiti', 'sqlmap', 'burpsuite', 'zap', 'owasp', 'metasploit',
  'openvas', 'nessus', 'acunetix', 'aircrack', 'john', 'hashcat',
  
  // Terminal / Shell
  'bash', 'zsh', 'fish', 'dash', 'sh', 'cmd.exe', 'terminal', 'xterm',
  'screen', 'tmux', 'alacritty', 'konsole', 'gnome-terminal', 'termux',
  
  // Programming Languages (Runtime)
  'python', 'python3', 'node', 'nodejs', 'deno', 'bun', 'ruby', 'perl', 'php',
  'go', 'rust', 'cargo', 'dotnet', 'mono', 'julia', 'lua', 'luajit',
  
  // Package Managers / Build Tools
  'npm', 'yarn', 'pnpm', 'pip', 'pip3', 'gem', 'composer', 'maven', 'gradle',
  'cargo', 'brew', 'apt', 'yum', 'dnf', 'pacman', 'nix', 'choco',
  
  // CI/CD / Automation
  'jenkins', 'gitlab-ci', 'github-actions', 'circleci', 'travis', 'drone',
  'argo', 'tekton', 'azure-pipelines', 'aws-codebuild',
  
  // Headless Browsers
  'puppeteer', 'playwright', 'selenium', 'phantomjs', 'headless', 'chromium-headless',
  'webkit', 'geckodriver', 'chromedriver', 'webdriver',
  
  // Monitoring / Testing
  'newrelic', 'datadog', 'dynatrace', 'appdynamics', 'splunk', 'elastic',
  'k6', 'jmeter', 'gatling', 'locust', 'artillery', 'loadrunner',
  
  // API Tools
  'swagger', 'openapi', 'graphql-playground', 'altair', 'voyager',
  'rapidapi', 'hurl', 'schemathesis', 'dredd',
  
  // Random/Anonymizer
  'tor', 'tor-browser', 'torsocks', 'proxychains', 'vpn', 'openvpn', 'wireguard',
  
  // Custom / Spoofed
  'roblox/linux', 'roblox/windows', 'roblox/macos', 'http-service',
  'mxhytz', 'corp', 'aether', 'protect', 'bypass', 'crawler', 'scraper', 'bot'
];

// Fungsi deteksi tools dengan regex pattern
function isBlacklistedTool(userAgent) {
  const uaLower = userAgent.toLowerCase();
  
  // Cek exact match
  for (const tool of BLACKLISTED_TOOLS) {
    if (uaLower.includes(tool.toLowerCase())) {
      return tool;
    }
  }
  
  // Deteksi pola mencurigakan
  const suspiciousPatterns = [
    /robots\.txt/i,           // Scanner
    /\.\.\/\.\.\//i,          // Path traversal
    /\%[0-9a-f]{2}/i,         // URL encoded
    /\/etc\/passwd/i,         // LFI attempt
    /union.*select/i,         // SQL injection
    /<script>/i,              // XSS attempt
    /localhost/i,             // SSRF attempt
    /169\.254\./i,            // AWS metadata
    /100\.100\.100\.100/i,    // SSRF detection
  ];
  
  for (const pattern of suspiciousPatterns) {
    if (pattern.test(userAgent)) {
      return 'suspicious_pattern';
    }
  }
  
  return false;
}

// Fungsi deteksi header aneh (ro-http.js punya signature unik)
function isSuspiciousHeaders(headers) {
  const suspicious = [];
  
  // Cek header order yang tidak wajar
  const headerKeys = Object.keys(headers);
  if (headerKeys.includes('accept-encoding') && 
      headerKeys.includes('connection') && 
      !headerKeys.includes('accept-language')) {
    suspicious.push('minimal_headers');
  }
  
  // Cek user-agent palsu (Roblox tapi aneh)
  const ua = headers['user-agent'] || '';
  if (ua.includes('Roblox') && !ua.includes('robloxstudio')) {
    // Cek apakah ada signature aneh
    if (ua.includes('compatible') || ua.includes('Linux') || ua.includes('HttpService')) {
      suspicious.push('fake_roblox_ua');
    }
  }
  
  return suspicious.length > 0;
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
      city: data?.location?.city || 'Unknown',
      isp: data?.network?.organization || 'Unknown'
    };
  } catch (err) {
    console.error('ipapi.is error:', err);
    return { is_vpn: false, is_proxy: false, is_datacenter: false, country: 'Unknown', city: 'Unknown', isp: 'Unknown' };
  }
}

// Fungsi generate salted token
function generateSaltedToken() {
  const utcHour = Math.floor(Date.now() / 3600000);
  const rawString = utcHour + "PINAT_SALT_77_V2";
  return Buffer.from(rawString).toString('base64');
}

function validateToken(token) {
  if (!token) return false;
  const expectedToken = generateSaltedToken();
  return token === expectedToken;
}

// Enhanced Discord logging dengan detail lengkap
async function sendDiscordLog(ip, reason, ua, hwid = null, location = null, headers = null, toolDetected = null, gameType = null) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const fields = [
    { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🛡️ Reason", value: `\`${reason}\``, inline: true },
    { name: "⏰ Timestamp", value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }), inline: true }
  ];

  if (toolDetected) {
    fields.splice(1, 0, { name: "🔧 Detected Tool", value: `\`${toolDetected}\``, inline: true });
  }
  
  if (hwid) fields.push({ name: "🔑 HWID", value: `\`${hwid}\``, inline: true });
  if (location?.country && location.country !== 'Unknown') {
    fields.push({ name: "🌍 Country", value: `\`${location.country}\``, inline: true });
    fields.push({ name: "🏙️ City", value: `\`${location.city}\``, inline: true });
    fields.push({ name: "🏢 ISP", value: `\`${location.isp}\``, inline: true });
  }
  if (gameType) fields.push({ name: "🎮 Trap Game", value: `\`${gameType}\``, inline: true });
  fields.push({ name: "📱 User Agent", value: `\`${ua.substring(0, 150)}\``, inline: false });

  const data = {
    username: "🔒 Pinat Guard System v6",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 SKIDDER DETECTED & PERMABANNED!",
      color: 15158332,
      fields: fields,
      footer: { text: "PinatHub Security Protection v6 - Zero Trust Security" },
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

function renderBlacklistPage(ip, hwid = null, reason = null) {
  return `<!DOCTYPE html>
    <html lang="id"><head><meta charset="UTF-8"><title>🔒 Access Denied - PinatHub Security</title>
    <style>
      body{background:#0a0a0a;color:#fff;font-family:'Courier New',monospace;display:flex;justify-content:center;align-items:center;height:100vh;margin:0;text-align:center;}
      .content{max-width:600px;padding:40px;background:#111;border:1px solid #ff0000;border-radius:8px;box-shadow:0 0 20px rgba(255,0,0,0.3);}
      h1{font-size:48px;font-weight:700;margin:0;color:#ff0000;text-shadow:0 0 10px rgba(255,0,0,0.5);}
      h2{font-size:20px;margin:20px 0;color:#ff6666;}
      p{color:#888;font-size:14px;line-height:1.6;margin:20px 0;}
      .badge{background:#ff0000;color:#fff;padding:6px 16px;border-radius:4px;font-size:11px;font-weight:bold;text-transform:uppercase;margin-bottom:20px;display:inline-block;letter-spacing:2px;}
      .footer{margin-top:30px;font-size:11px;color:#444;border-top:1px solid #333;padding-top:20px;font-family:monospace;}
      .reason{color:#ff8888;font-size:12px;background:#1a0000;padding:10px;border-radius:4px;margin:20px 0;}
    </style>
    </head><body><div class="content"><div class="badge">🚫 PERMANENT BAN 🚫</div>
    <h1>ACCESS DENIED</h1>
    <h2>skidder tool detected & blacklisted</h2>
    <div class="reason">🔍 Reason: ${reason || 'Blacklisted Tool / Illegal Access'}</div>
    <p>${hwid ? 'Device ID' : 'IP Address'} <strong>${hwid || ip}</strong> has been permanently banned from PinatHub services.<br>
    Your request was logged and reported to security team.<br><br>
    🛡️ <em>This is not a game. Stop trying to steal assets.</em></p>
    <div class="footer">case_id: ${Math.random().toString(36).substring(2, 10).toUpperCase()}<br>timestamp: ${new Date().toISOString()}<br>security_level: MAXIMUM</div>
    </div></body></html>`;
}

// ============ 7 PERMAINAN BERBEDA ============

// Game 1: TEBAK ANGKA (1-100)
function gameNumberGuess() {
  const target = Math.floor(Math.random() * 100) + 1;
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">🎲</div>
        <h3>Tebak Angka 1-100</h3>
        <p>tebak angka yang dipikirkan sistem</p>
        <input type="number" id="guessInput" placeholder="masukkan angka..." min="1" max="100">
        <button class="option" onclick="checkGuess(${target})">tebak!</button>
        <div id="gameFeedback"></div>
      </div>
      <script>
        let attempts = 0;
        function checkGuess(target) {
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
        }
      </script>
    `,
    name: "Number Guessing Game"
  };
}

// Game 2: CLICK SPEED TEST
function gameClickSpeed() {
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">⚡</div>
        <h3>Click Speed Test</h3>
        <p>klik tombol ini 10x secepat mungkin!</p>
        <button class="option" id="clickBtn" style="background:#000;color:#fff;">0/10</button>
        <div id="clickTimer"></div>
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
              document.getElementById('clickTimer').innerHTML = '<span style="color:green;">✅ ' + time + ' detik - kenceng juga!</span>';
              setTimeout(() => next(), 1500);
            } else {
              document.getElementById('clickTimer').innerHTML = '<span style="color:red;">🐌 lemot amat ' + time + ' detik! banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            }
          }
        };
      </script>
    `,
    name: "Click Speed Test"
  };
}

// Game 3: TEKA-TEKI LOGIKA
function gameRiddle() {
  const riddles = [
    { q: "Apa yang naik tapi gak pernah turun?", a: "umur", hint: "usia" },
    { q: "Semakin banyak diambil semakin besar, apa hayo?", a: "lubang", hint: "bolong" },
    { q: "Bisa terbang tanpa sayap, menangis tanpa mata?", a: "awan", hint: "langit" },
    { q: "Punya gigi tapi gak bisa makan?", a: "sisir", hint: "rambut" },
    { q: "Kalau dipencet keluar air, tapi bukan pipa?", a: "jerawat", hint: "wajah" }
  ];
  const riddle = riddles[Math.floor(Math.random() * riddles.length)];
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">🧠</div>
        <h3>Teka-Teki Logika</h3>
        <p><strong>${riddle.q}</strong></p>
        <input type="text" id="riddleAnswer" placeholder="jawaban...">
        <button class="option" onclick="checkRiddle('${riddle.a}', '${riddle.hint}')">jawab!</button>
        <div id="riddleFeedback"></div>
      </div>
      <script>
        let attempts = 0;
        function checkRiddle(answer, hint) {
          const userAnswer = document.getElementById('riddleAnswer').value.toLowerCase().trim();
          attempts++;
          if(userAnswer === answer) {
            document.getElementById('riddleFeedback').innerHTML = '<span style="color:green;">🎉 pinter! lanjut...</span>';
            setTimeout(() => next(), 1500);
          } else if(attempts >= 2) {
            document.getElementById('riddleFeedback').innerHTML = '<span style="color:red;">💀 hint: ' + hint + ' - gagal 2x, banned!</span>';
            setTimeout(() => window.location.href = window.location.href, 2000);
          } else {
            document.getElementById('riddleFeedback').innerHTML = '<span style="color:orange;">❌ salah! coba lagi...</span>';
          }
        }
      </script>
    `,
    name: "Logic Riddle"
  };
}

// Game 4: MATCHING PAIRS (Memory Game)
function gameMemory() {
  const emojis = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊'];
  const doubled = [...emojis, ...emojis];
  for (let i = doubled.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [doubled[i], doubled[j]] = [doubled[j], doubled[i]];
  }
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">🎴</div>
        <h3>Memory Match</h3>
        <p>cocokin pasangan emoji yang sama!</p>
        <div id="memoryGrid" style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:20px 0;"></div>
        <div id="memoryStatus"></div>
      </div>
      <script>
        const cards = ${JSON.stringify(doubled)};
        let opened = [], matched = [], moves = 0;
        const grid = document.getElementById('memoryGrid');
        function render() {
          grid.innerHTML = cards.map((card, i) => 
            '<button class="option" style="font-size:24px;padding:15px;" onclick="flip(' + i + ')" ' + 
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
                document.getElementById('memoryStatus').innerHTML = '<span style="color:green;">🎉 menang! lanjut...</span>';
                setTimeout(() => next(), 1500);
              }
            } else {
              setTimeout(() => { opened = []; render(); }, 500);
            }
          }
          render();
          if(moves > 20) {
            document.getElementById('memoryStatus').innerHTML = '<span style="color:red;">💀 terlalu banyak gerakan! banned!</span>';
            setTimeout(() => window.location.href = window.location.href, 2000);
          }
        };
        render();
      </script>
    `,
    name: "Memory Match Game"
  };
}

// Game 5: MATH CHALLENGE
function gameMath() {
  const num1 = Math.floor(Math.random() * 50) + 10;
  const num2 = Math.floor(Math.random() * 50) + 10;
  const ops = ['+', '-', '*'];
  const op = ops[Math.floor(Math.random() * ops.length)];
  let result;
  if (op === '+') result = num1 + num2;
  else if (op === '-') result = num1 - num2;
  else result = num1 * num2;
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">🧮</div>
        <h3>Math Challenge</h3>
        <p>hitung: ${num1} ${op} ${num2} = ?</p>
        <input type="number" id="mathAnswer" placeholder="jawaban...">
        <button class="option" onclick="checkMath(${result})">hitung!</button>
        <div id="mathFeedback"></div>
      </div>
      <script>
        let attempts = 0;
        function checkMath(result) {
          const answer = parseInt(document.getElementById('mathAnswer').value);
          attempts++;
          if(answer === result) {
            document.getElementById('mathFeedback').innerHTML = '<span style="color:green;">🎉 pinter matematika! lanjut...</span>';
            setTimeout(() => next(), 1500);
          } else if(attempts >= 3) {
            document.getElementById('mathFeedback').innerHTML = '<span style="color:red;">💀 gagal 3x, dasar bego! banned!</span>';
            setTimeout(() => window.location.href = window.location.href, 2000);
          } else {
            document.getElementById('mathFeedback').innerHTML = '<span style="color:orange;">❌ salah! coba lagi...</span>';
          }
        }
      </script>
    `,
    name: "Math Challenge"
  };
}

// Game 6: TYPING SPEED
function gameTyping() {
  const words = ['javascript', 'pinathub', 'skidder', 'security', 'roblox', 'hacker'];
  const target = words[Math.floor(Math.random() * words.length)];
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">⌨️</div>
        <h3>Typing Speed Test</h3>
        <p>ketik ulang kata ini: <strong style="font-size:24px;background:#f0f0f0;padding:10px;display:block;">${target}</strong></p>
        <input type="text" id="typeInput" placeholder="ketik di sini...">
        <button class="option" onclick="checkTyping('${target}')">submit!</button>
        <div id="typeFeedback"></div>
      </div>
      <script>
        let startTime = Date.now();
        function checkTyping(target) {
          const userInput = document.getElementById('typeInput').value.toLowerCase().trim();
          const time = (Date.now() - startTime) / 1000;
          if(userInput === target) {
            if(time < 10) {
              document.getElementById('typeFeedback').innerHTML = '<span style="color:green;">🎉 ' + time + ' detik - cepet amat!</span>';
              setTimeout(() => next(), 1500);
            } else {
              document.getElementById('typeFeedback').innerHTML = '<span style="color:red;">🐌 ' + time + ' detik - pelan amat! banned!</span>';
              setTimeout(() => window.location.href = window.location.href, 2000);
            }
          } else {
            document.getElementById('typeFeedback').innerHTML = '<span style="color:red;">❌ salah ngetik! banned langsung!</span>';
            setTimeout(() => window.location.href = window.location.href, 2000);
          }
        }
      </script>
    `,
    name: "Typing Speed Test"
  };
}

// Game 7: ROCK PAPER SCISSORS (Best of 3)
function gameRPS() {
  return {
    html: `
      <div class="game-container">
        <div class="game-icon">✊</div>
        <h3>Rock Paper Scissors</h3>
        <p>best of 3 - kalahkan AI!</p>
        <div style="display:flex;gap:10px;justify-content:center;margin:20px 0;">
          <button class="option" onclick="playRPS('rock')">✊ Batu</button>
          <button class="option" onclick="playRPS('paper')">✋ Kertas</button>
          <button class="option" onclick="playRPS('scissors')">✌️ Gunting</button>
        </div>
        <div id="rpsScore">Skor: Player 0 - 0 AI</div>
        <div id="rpsResult"></div>
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
            document.getElementById('rpsResult').innerHTML = '<span style="color:green;">🎉 menang! lanjut...</span>';
            setTimeout(() => next(), 1500);
          } else if(aiScore === 2) {
            document.getElementById('rpsResult').innerHTML = '<span style="color:red;">💀 kalah dari AI! banned!</span>';
            setTimeout(() => window.location.href = window.location.href, 2000);
          } else {
            document.getElementById('rpsResult').innerHTML = '<span style="color:orange;">' + result + '! lanjut game ' + (playerScore + aiScore + 1) + '/3</span>';
          }
        }
      </script>
    `,
    name: "Rock Paper Scissors"
  };
}

// Pilih game random
function getRandomGame() {
  const games = [gameNumberGuess, gameClickSpeed, gameRiddle, gameMemory, gameMath, gameTyping, gameRPS];
  const selected = games[Math.floor(Math.random() * games.length)];
  return selected();
}

export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const xForwardedFor = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;
  const xHwid = req.headers['x-hwid'];
  const clientToken = req.headers['x-pinat-auth'];

  // ============ DETEKSI TOOLS ILEGAL (WAJIB PALING DEPAN!) ============
  const detectedTool = isBlacklistedTool(userAgent);
  const hasSuspiciousHeaders = isSuspiciousHeaders(req.headers);
  
  if (detectedTool || hasSuspiciousHeaders) {
    try {
      await client.connect();
      const db = client.db('pinat_protection');
      const blacklist = db.collection('blacklisted_ips');
      
      const reason = detectedTool 
        ? `blacklisted_tool: ${detectedTool}` 
        : 'suspicious_headers_detected';
      
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        hwid: xHwid || null,
        reason: reason,
        headers: JSON.stringify(req.headers),
        date: new Date() 
      });
      
      const vpnCheck = await checkVpnProxy(xForwardedFor);
      await sendDiscordLog(
        xForwardedFor, 
        `🚫 BLACKLISTED TOOL DETECTED`, 
        userAgent, 
        xHwid, 
        vpnCheck, 
        req.headers, 
        detectedTool || 'Suspicious Headers'
      );
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(xForwardedFor, xHwid, reason));
    } catch (err) {
      console.error(err);
      return res.status(403).send('Access Denied - Blacklisted Tool');
    }
  }

  // Region Lock (Indonesia Only)
  const countryCode = req.headers['x-vercel-ip-country'] || '';
  if (countryCode !== 'ID') {
    await sendDiscordLog(xForwardedFor, `REGION LOCK: ${countryCode} (bukan Indonesia)`, userAgent, xHwid);
    return res.status(403).send('Access Denied: This service is only available in Indonesia.');
  }

  // Deteksi Roblox ASLI (BUKAN SPOOF)
  const isRealRoblox = userAgent.includes('roblox') && 
                       !userAgent.includes('node') &&
                       !userAgent.includes('axios') &&
                       !userAgent.includes('fetch') &&
                       !userAgent.includes('python');

  if (isRealRoblox) {
    try {
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-5');
      let content = await response.text();
      const hexEncoded = Buffer.from(content).toString('hex');
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(hexEncoded);
    } catch (err) {
      return res.status(500).send('2d2d205b70696e61746875622d6572726f725d3a20736f75726365206f66666c696e652e');
    }
  }

  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('blacklisted_ips');

    // Cek blacklist (IP atau HWID)
    const queryConditions = [{ ip: xForwardedFor }];
    if (xHwid) queryConditions.push({ hwid: xHwid });
    const blocked = await blacklist.findOne({ $or: queryConditions });
    if (blocked) {
      return res.status(403).send(renderBlacklistPage(xForwardedFor, blocked.hwid, blocked.reason));
    }

    // Validasi token
    if (!validateToken(clientToken)) {
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: 'invalid_token_http_hook', date: new Date() });
      const vpnCheck = await checkVpnProxy(xForwardedFor);
      await sendDiscordLog(xForwardedFor, "Invalid Token (HTTP Hook Attempt)", userAgent, xHwid, vpnCheck, req.headers);
      return res.status(403).send(renderBlacklistPage(xForwardedFor, xHwid, 'Invalid Authentication Token'));
    }

    // Cek VPN/Proxy
    const vpnCheck = await checkVpnProxy(xForwardedFor);
    if (vpnCheck.is_vpn || vpnCheck.is_proxy || vpnCheck.is_datacenter) {
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: 'vpn_proxy_detected', date: new Date() });
      await sendDiscordLog(xForwardedFor, "VPN/Proxy/DC Detected", userAgent, xHwid, vpnCheck, req.headers);
      return res.status(403).send(renderBlacklistPage(xForwardedFor, xHwid, 'VPN/Proxy not allowed'));
    }

    // POST = gagal kuis (untuk browser yang kena game trap)
    if (req.method === 'POST') {
      const gameName = req.headers['x-game-type'] || 'unknown';
      await blacklist.insertOne({ ip: xForwardedFor, hwid: xHwid || null, reason: `failed_game_trap_${gameName}`, date: new Date() });
      await sendDiscordLog(xForwardedFor, `Failed Game Trap (${gameName})`, userAgent, xHwid, vpnCheck, null, null, gameName);
      return res.status(200).json({ status: 'blacklisted' });
    }

    // Jika semua lolos, beri akses langsung (tanpa game trap untuk Roblox asli)
    try {
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-5');
      let content = await response.text();
      const hexEncoded = Buffer.from(content).toString('hex');
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(hexEncoded);
    } catch (err) {
      return res.status(500).send('2d2d205b70696e61746875622d6572726f725d3a20736f75726365206f66666c696e652e');
    }

  } catch (err) {
    console.error(err);
    return res.status(500).send('2d2d205b70696e61746875622d6572726f725d3a20696e7465726e616c20736572766572206572726f722e');
  }
}
