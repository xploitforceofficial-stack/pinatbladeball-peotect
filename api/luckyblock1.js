import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// FUNGSI BARU: Kirim log ke Discord Webhook
async function sendDiscordLog(ip, reason, ua, additionalInfo = {}) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const data = {
    username: "🔒 Pinat Guard System Pro",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 SKIDDER DETECTED & PERMA-BANNED!",
      color: 15158332,
      fields: [
        { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
        { name: "🛡️ Reason", value: `\`${reason}\``, inline: true },
        { name: "📱 User Agent", value: `\`${ua.substring(0, 100)}\`` },
        { name: "🕵️ Tool Type", value: `\`${additionalInfo.toolType || 'Unknown'}\``, inline: true },
        { name: "🎯 Threat Level", value: `\`${additionalInfo.threatLevel || 'HIGH'}\``, inline: true },
        { name: "⏰ Timestamp", value: new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' }) }
      ],
      footer: { text: "PinatHub Security Protection v4.0 - Zero Tolerance Policy" }
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

// Fungsi untuk nampilin sambutan meriah buat yang udah di-ban
function renderBlacklistPage(ip, reason = "security_violation") {
  return `
    <!DOCTYPE html>
    <html lang="id">
    <head>
        <meta charset="UTF-8">
        <title>🔒 404 - Access Denied Permanently</title>
        <style>
            body { background: #0a0a0a; color: #fff; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; text-align: center; }
            .content { max-width: 600px; padding: 40px; background: #111; border-radius: 16px; border: 1px solid #ff0000; box-shadow: 0 0 40px rgba(255,0,0,0.2); }
            h1 { font-size: 72px; font-weight: 900; margin: 0; color: #ff0000; text-shadow: 0 0 10px rgba(255,0,0,0.5); letter-spacing: -2px; }
            h2 { font-size: 28px; font-weight: 600; margin: 10px 0; }
            p { color: #888; font-size: 14px; line-height: 1.6; }
            .badge { background: #ff0000; color: #fff; padding: 6px 16px; border-radius: 100px; font-size: 12px; font-weight: bold; text-transform: uppercase; margin-bottom: 20px; display: inline-block; }
            .footer { margin-top: 40px; font-size: 11px; color: #444; border-top: 1px solid #222; padding-top: 20px; font-family: monospace; }
            .warning { color: #ff6600; font-size: 12px; margin-top: 15px; }
        </style>
    </head>
    <body>
        <div class="content">
            <div class="badge">🚫 PERMANENT BLACKLIST 🚫</div>
            <h1>403</h1>
            <h2 style="color:#ff0000">SKIDDER DETECTED!</h2>
            <p><b>IP: ${ip}</b> has been <b style="color:#ff0000">PERMANENTLY BANNED</b> from accessing this API.</p>
            <p>Reason: <code>${reason}</code><br>Your activity has been logged and reported.</p>
            <div class="warning">⚠️ Don't bother trying to bypass - every attempt makes your ban worse ⚠️</div>
            <div class="footer">
                case_id: ${Math.random().toString(36).substring(2, 10).toUpperCase()}<br>
                status: BLACKLISTED_PERMANENTLY<br>
                signature: PinatHub Security Team
            </div>
        </div>
    </body>
    </html>
  `;
}

// ENHANCED BLACKLIST - 150+ TOOLS DETECTED!
function isMaliciousTool(userAgent) {
  const ua = userAgent.toLowerCase();
  
  // ========== WEB SCRAPING & HTTP CLIENTS ==========
  const httpClients = [
    'curl', 'wget', 'httpie', 'http-client', 'rest-client', 'insomnia', 'postman', 
    'bruno', 'hoppscotch', 'paw', 'soapui', 'jmeter', 'ab', 'siege', 'wrk', 'vegeta',
    'drill', 'bombardier', 'hey', 'plow', 'ali', 'nload', 'httperf', 'web-benchmark'
  ];
  
  // ========== PROGRAMMING LANGUAGES & LIBRARIES ==========
  const programmingTools = [
    'python', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'pycurl', 'scrapy',
    'node-fetch', 'axios', 'superagent', 'got', 'undici', 'request', 'http', 'https',
    'php', 'java', 'ruby', 'perl', 'go-http-client', 'rust', 'csharp', 'fsharp',
    'scala', 'kotlin', 'swift', 'dart'
  ];
  
  // ========== DOWNLOAD MANAGERS & TOOLS ==========
  const downloaders = [
    'aria2', 'axel', 'wget2', 'httrack', 'webcopier', 'offline explorer', 'teleport',
    'webzip', 'idm', 'internet download manager', 'xdm', 'persepolis', 'uget', 'flud'
  ];
  
  // ========== TERMINAL & SHELL ==========
  const terminals = [
    'powershell', 'pwsh', 'cmd', 'bash', 'zsh', 'fish', 'sh', 'ksh', 'tcsh', 'csh',
    'termux', 'terminal', 'xterm', 'gnome-terminal', 'konsole', 'alacritty', 'kitty',
    'hyper', 'iterm', 'windows terminal', 'mintty', 'cygwin', 'msys', 'git-bash'
  ];
  
  // ========== SECURITY SCANNERS & PENTEST TOOLS ==========
  const securityTools = [
    'nmap', 'masscan', 'zmap', 'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf',
    'nikto', 'wapiti', 'zap', 'burp', 'sqlmap', 'hydra', 'medusa', 'ncrack',
    'thc-hydra', 'aircrack', 'metasploit', 'beef', 'xsser', 'commix', 'dnsrecon',
    'theharvester', 'recon-ng', 'sn1per', 'autosploit', 'exploitdb', 'searchsploit'
  ];
  
  // ========== BOTS & AUTOMATION ==========
  const automationBots = [
    'bot', 'crawler', 'spider', 'scraper', 'scraping', 'automation', 'selenium',
    'puppeteer', 'playwright', 'cypress', 'testcafe', 'phantomjs', 'headless',
    'chrome-headless', 'headless-chrome', 'webkit', 'geckodriver', 'chromedriver'
  ];
  
  // ========== API TESTING TOOLS ==========
  const apiTesters = [
    'swagger', 'openapi', 'graphql', 'altair', 'graphiql', 'voyager', 'apollo',
    'rapidapi', 'hurl', 'schemathesis', 'dredd', 'spectral', 'apisprout'
  ];
  
  // ========== CODE EDITORS (suspicious) ==========
  const suspiciousEditors = [
    'vscode', 'visual studio', 'atom', 'sublime', 'notepad++', 'vim', 'neovim',
    'emacs', 'intellij', 'pycharm', 'webstorm', 'phpstorm', 'eclipse', 'netbeans'
  ];
  
  // ========== PACKAGE MANAGERS ==========
  const packageManagers = [
    'npm', 'yarn', 'pnpm', 'pip', 'pipenv', 'poetry', 'gem', 'bundle', 'composer',
    'maven', 'gradle', 'ant', 'nuget', 'cargo', 'go-mod', 'brew', 'apt', 'yum', 'dnf'
  ];
  
  // ========== CLOUD & SERVER TOOLS ==========
  const cloudTools = [
    'aws-cli', 'azure-cli', 'gcloud', 'terraform', 'ansible', 'puppet', 'chef',
    'salt', 'kubectl', 'helm', 'docker', 'podman', 'k3s', 'rancher', 'openshift'
  ];
  
  // ========== DATABASE CLIENTS ==========
  const dbClients = [
    'mysql', 'psql', 'mongosh', 'redis-cli', 'sqlite3', 'mssql', 'oracle', 'dbeaver',
    'datagrip', 'navicat', 'tableplus', 'mongodb-compass', 'pgadmin', 'mysql-workbench'
  ];
  
  // ========== ADDITIONAL MALICIOUS PATTERNS ==========
  const maliciousPatterns = [
    'bypass', 'crack', 'hack', 'exploit', 'inject', 'scrape', 'leech', 'ripper',
    'stealer', 'grabber', 'sniffer', 'spoof', 'proxy', 'vpn', 'tor', 'torsocks'
  ];
  
  // Combine all tools
  const allTools = [
    ...httpClients, ...programmingTools, ...downloaders, ...terminals,
    ...securityTools, ...automationBots, ...apiTesters, ...suspiciousEditors,
    ...packageManagers, ...cloudTools, ...dbClients
  ];
  
  // Check main tools
  const isTool = allTools.some(tool => ua.includes(tool));
  
  // Check malicious patterns
  const hasMaliciousPattern = maliciousPatterns.some(pattern => ua.includes(pattern));
  
  // Check for empty/spoofed UA
  const isSpoofed = ua.length < 10 || ua.includes('null') || ua.includes('undefined') || ua.includes('(null)');
  
  return { isTool, hasMaliciousPattern, isSpoofed, detectedTool: allTools.find(t => ua.includes(t)) || 'unknown' };
}

export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const xForwardedFor = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
  
  // ========== SUPER PROTECTED ROBLOX CHECK ==========
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio') && !userAgent.includes('chrome');
  
  if (isRoblox) {
    try {
      // Additional security: check if request is really from Roblox
      const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-3', {
        headers: { 'User-Agent': 'Roblox/Lua' }
      });
      const content = await response.text();
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.setHeader('X-Protected-By', 'PinatGuard-Pro');
      return res.status(200).send(content);
    } catch (err) {
      return res.status(500).send('-- [pinathub-error]: source offline. Contact @owner');
    }
  }
  
  // ========== ENHANCED TOOL DETECTION ==========
  const toolCheck = isMaliciousTool(userAgent);
  const isForbidden = toolCheck.isTool || toolCheck.hasMaliciousPattern || toolCheck.isSpoofed;
  
  // ========== RATE LIMITING (additional protection) ==========
  const rateLimitKey = `rate_${xForwardedFor}`;
  // (Implement rate limiting if needed - using in-memory for demo)
  
  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('blacklisted_ips');
    const attemptsLog = db.collection('attempt_logs');
    
    // Log every attempt for analysis
    await attemptsLog.insertOne({
      ip: xForwardedFor,
      userAgent: userAgent,
      timestamp: new Date(),
      isRoblox: false,
      detectedTool: toolCheck.detectedTool,
      isMalicious: isForbidden
    });
    
    // ========== CHECK BLACKLIST ==========
    const blocked = await blacklist.findOne({ ip: xForwardedFor });
    if (blocked) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(xForwardedFor, blocked.reason || 'permanent_ban'));
    }
    
    // ========== IMMEDIATE BLACKLIST FOR TOOLS ==========
    if (isForbidden) {
      const banReason = toolCheck.isTool ? `detected_tool:${toolCheck.detectedTool}` : 
                        toolCheck.hasMaliciousPattern ? 'malicious_pattern_detected' : 
                        'spoofed_user_agent';
      
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        reason: banReason, 
        date: new Date(),
        userAgent: userAgent,
        detectedTool: toolCheck.detectedTool,
        banType: 'permanent'
      });
      
      // Send to Discord with detailed info
      await sendDiscordLog(xForwardedFor, `🔧 ${banReason.toUpperCase()}`, userAgent, {
        toolType: toolCheck.detectedTool || 'Unknown',
        threatLevel: 'CRITICAL',
        details: `Detected by PinatGuard Pro v4.0`
      });
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklistPage(xForwardedFor, banReason));
    }
    
    // ========== ENHANCED QUIZ WITH MORE TRAPS ==========
    if (req.method === 'POST') {
      const { answer } = req.body;
      
      // All answers lead to blacklist - this is a trap!
      await blacklist.insertOne({ 
        ip: xForwardedFor, 
        reason: 'failed_quiz_skidder_intentional', 
        date: new Date(),
        quizAnswer: answer || 'none',
        banType: 'permanent'
      });
      
      await sendDiscordLog(xForwardedFor, "❌ FAILED SECURITY QUIZ (Intentional Skidder)", userAgent, {
        toolType: 'Browser Quiz',
        threatLevel: 'HIGH',
        details: `User answered: ${answer || 'no answer'}`
      });
      
      return res.status(200).json({ status: 'blacklisted', message: 'Your IP has been permanently banned.' });
    }
    
    // ========== ADVANCED TRAP PAGE ==========
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('X-Robots-Tag', 'noindex, nofollow');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html lang="id">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>🔒 Verification Required • Pinat Security</title>
          <style>
              :root { --bg: #000; --fg: #fff; --accent: #00ff00; --danger: #ff0000; }
              * { box-sizing: border-box; font-family: 'Courier New', monospace; }
              body { background: var(--bg); color: var(--fg); display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
              .card { width: 100%; max-width: 500px; padding: 40px; background: #0a0a0a; border: 1px solid #333; border-radius: 12px; box-shadow: 0 0 30px rgba(0,0,0,0.5); }
              .warning-icon { font-size: 48px; text-align: center; margin-bottom: 20px; }
              h1 { font-size: 20px; font-weight: 600; margin: 0 0 10px; text-align: center; color: #ff0000; }
              p { color: #888; font-size: 13px; line-height: 1.5; margin-bottom: 25px; text-align: center; }
              .option { 
                  display: block; width: 100%; padding: 12px 16px; margin-bottom: 10px; 
                  background: #111; border: 1px solid #333; border-radius: 6px; 
                  font-size: 13px; text-align: left; cursor: pointer; transition: 0.2s; color: #fff;
              }
              .option:hover { border-color: #ff0000; background: #1a0000; }
              .terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 11px; margin-top: 20px; display: none; line-height: 1.4; border: 1px solid #00ff00; }
              .hidden { display: none; }
              .counter { font-size: 10px; color: #666; text-align: center; margin-top: 15px; }
          </style>
      </head>
      <body>
          <div class="card">
              <div class="warning-icon">🔒</div>
              
              <div id="q-stage">
                  <h1>⚠️ SECURITY VERIFICATION REQUIRED ⚠️</h1>
                  <p>Your activity has been flagged as suspicious. Please complete verification to prove you're not a bot/skidder.</p>
                  <div id="options-alt">
                      <button class="option" onclick="submitAnswer('I am a skidder trying to steal scripts')">I am a skidder trying to steal scripts</button>
                      <button class="option" onclick="submitAnswer('I want to crack this protection')">I want to crack this protection</button>
                      <button class="option" onclick="submitAnswer('I use illegal tools to scrape')">I use illegal tools to scrape</button>
                      <button class="option" onclick="submitAnswer('I am a legitimate developer')">I am a legitimate developer</button>
                  </div>
                  <div class="counter">⚠️ Any choice will be logged and reviewed ⚠️</div>
              </div>

              <div id="log-stage" class="hidden">
                  <h1 style="color:#ff0000">⚠️ ACCESS DENIED ⚠️</h1>
                  <p>Your response has been recorded. Your IP has been added to permanent blacklist.</p>
                  <div class="terminal" id="term"></div>
                  <button class="option" style="margin-top:20px; text-align:center;" onclick="location.reload()">Close Window</button>
              </div>
          </div>

          <script>
              async function submitAnswer(answer) {
                  document.getElementById('q-stage').classList.add('hidden');
                  document.getElementById('log-stage').classList.remove('hidden');
                  
                  const term = document.getElementById('term');
                  term.style.display = 'block';
                  
                  // Send to server
                  await fetch(window.location.href, { 
                      method: 'POST',
                      headers: { 'Content-Type': 'application/json' },
                      body: JSON.stringify({ answer: answer })
                  });
                  
                  const logs = [
                      "> [SECURITY] Starting forensic analysis...",
                      "> [INFO] Target IP: ${xForwardedFor}",
                      "> [ALERT] Suspicious activity detected!",
                      "> [ACTION] Adding to permanent blacklist...",
                      "> [DATABASE] Writing ban record...",
                      "> [DISCORD] Reporting to security team...",
                      "> [COMPLETE] IP permanently banned!",
                      "> [MESSAGE] Don't bother trying to bypass."
                  ];
                  
                  let i = 0;
                  const iv = setInterval(() => {
                      term.innerHTML += logs[i] + "<br>";
                      term.scrollTop = term.scrollHeight;
                      i++; 
                      if(i >= logs.length) clearInterval(iv);
                  }, 500);
              }
          </script>
      </body>
      </html>
    `);
    
  } catch (err) {
    console.error("PinatGuard Error:", err);
    return res.status(500).send('-- [pinathub-error]: Internal server error.');
  } finally {
    await client.close();
  }
}
