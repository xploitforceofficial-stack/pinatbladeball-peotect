import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// PIApi Configuration
const PIAPI_KEY = "c5473140651f84c8d9ba";
const PIAPI_BASE_URL = "https://piapi.org/api";

// Whitelist IPs (Full access - never restricted)
const WHITELIST_IPS = [
  '202.58.78.11',
  '202.58.78.9',
  '202.58.78.13',
  '127.0.0.1',
  '::1'
];

function isWhitelisted(ip) {
  return WHITELIST_IPS.includes(ip);
}

// PIApi data fetch with more details
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

function detectProxyVpn(piData) {
  if (!piData) return null;
  if (piData.is_proxy) return 'Proxy';
  if (piData.is_vpn) return 'VPN';
  if (piData.is_tor) return 'TOR';
  if (piData.is_datacenter && !piData.company?.name?.includes('Google')) return 'Datacenter';
  return null;
}

// Extended forbidden tools detection
const FORBIDDEN_TOOLS = [
  // Terminal/Shell
  'powershell', 'pwsh', 'cmd', 'command prompt', 'terminal', 'termux', 'bash', 'zsh', 'sh', 'ksh', 'fish', 'dash',
  'xterm', 'konsole', 'gnome-terminal', 'alacritty', 'kitty', 'hyper', 'iterm', 'windows terminal',
  
  // HTTP Clients
  'curl', 'wget', 'fetch', 'httpie', 'xh', 'hurl', 'restclient', 'postman', 'insomnia', 'bruno', 'hoppscotch', 'paw', 'rested',
  'apachebench', 'ab', 'siege', 'wrk', 'vegeta', 'hey', 'boom', 'jmeter', 'gatling', 'locust', 'k6', 'artillery',
  
  // Programming Languages
  'python', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'http.client', 'node-fetch', 'axios', 'superagent', 'got', 'request', 'undici',
  'php', 'curl.php', 'java', 'okhttp', 'apache-httpclient', 'ruby', 'net-http', 'faraday', 'go-http-client', 'rust-reqwest',
  'perl', 'lwp', 'wget-perl', 'csharp', 'restsharp', 'swift', 'alamofire', 'kotlin', 'ktor',
  
  // Automation/Bot
  'selenium', 'puppeteer', 'playwright', 'cypress', 'webdriver', 'headless', 'phantomjs', 'casperjs', 'zombie.js', 'nightmare',
  'taiko', 'testcafe', 'nightwatch', 'protractor', 'robotframework',
  
  // Security Tools
  'nmap', 'masscan', 'zmap', 'hydra', 'medusa', 'ncrack', 'sqlmap', 'burpsuite', 'owasp', 'zap', 'nikto', 'wpscan',
  'dirb', 'gobuster', 'ffuf', 'wfuzz', 'dirbuster', 'aircrack', 'john', 'hashcat', 'metasploit', 'beef',
  
  // Download Tools
  'aria2', 'axel', 'wget2', 'lwp-request', 'gdown', 'youtube-dl', 'yt-dlp', 'ffmpeg', 'rtmpdump', 'streamlink',
  
  // Crawler/Spider
  'scrapy', 'beautifulsoup', 'crawler', 'spider', 'bot', 'googlebot', 'bingbot', 'slurp', 'duckduckbot', 'baiduspider',
  'yandexbot', 'facebot', 'ia_archiver', 'ahrefs', 'semrush', 'mj12bot', 'rogerbot', 'exabot', 'dotbot',
  
  // Proxy/VPN tools
  'proxychains', 'torify', 'nordvpn', 'expressvpn', 'surfshark', 'protonvpn', 'openvpn', 'wireguard',
  
  // Code editors with automation
  'vscode', 'cursor', 'windsurf', 'continue', 'copilot', 'tabnine', 'kite',
  
  // API testing
  'swagger', 'postman-runtime', 'newman', 'soapui', 'apic',
  
  // CI/CD
  'jenkins', 'github-actions', 'gitlab-ci', 'circleci', 'travis', 'azure-pipelines', 'bitbucket-pipelines',
  
  // Database tools
  'mongodump', 'mongorestore', 'mysqldump', 'pgdump', 'redis-cli',
  
  // SSH tools
  'ssh', 'putty', 'winscp', 'filezilla', 'sftp', 'scp', 'rsync',
  
  // Network scanning
  'netcat', 'nc', 'telnet', 'dig', 'nslookup', 'host', 'whois', 'traceroute', 'mtr', 'ping',
  
  // Packet manipulation
  'tcpdump', 'wireshark', 'tshark', 'ettercap', 'bettercap', 'mitmproxy', 'burp',
  
  // Reverse engineering
  'gdb', 'lldb', 'radare2', 'ghidra', 'ida', 'objdump', 'strings', 'strace', 'ltrace',
  
  // Container tools
  'docker', 'podman', 'kubectl', 'helm', 'k3s', 'rancher',
  
  // Cloud CLI
  'aws', 'aws-cli', 'gcloud', 'az', 'azure-cli', 'terraform', 'pulumi',
  
  // Package managers
  'npm', 'yarn', 'pnpm', 'pip', 'pip3', 'gem', 'cargo', 'composer', 'gradle', 'maven',
  
  // Build tools
  'make', 'cmake', 'gcc', 'g++', 'clang', 'rustc', 'go-build', 'javac',
  
  // Monitoring
  'prometheus', 'grafana', 'datadog', 'newrelic', 'dynatrace', 'splunk',
  
  // Browser automation
  'puppeteer-extra', 'playwright-extra', 'stealth-plugin', 'undetected-chromedriver'
];

function detectForbiddenTool(userAgent) {
  const ua = userAgent.toLowerCase();
  
  const highPriority = ['powershell', 'pwsh', 'terminal', 'termux', 'cmd', 'bash', 'zsh', 'python', 'curl', 'wget', 'nmap', 'sqlmap'];
  
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

// COMPREHENSIVE DISCORD WEBHOOK WITH ALL DETAILS
async function sendDiscordLog(ip, reason, ua, toolInfo = null, piData = null, additionalInfo = {}) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  // Build comprehensive fields array
  const fields = [];
  
  // IP Information Section
  fields.push(
    { name: "━━━━━━━━━━━━━━━━━━━━", value: "🌐 IP INFORMATION", inline: false },
    { name: "📡 IP Address", value: `\`${ip}\``, inline: true },
    { name: "🎯 Detection Reason", value: `\`${reason}\``, inline: true }
  );
  
  // Timestamp
  fields.push({
    name: "⏰ Timestamp (UTC)",
    value: `\`${new Date().toISOString()}\``,
    inline: true
  });
  
  // User Agent Section
  fields.push(
    { name: "━━━━━━━━━━━━━━━━━━━━", value: "💻 USER AGENT", inline: false },
    { name: "🔧 Full User Agent", value: `\`\`\`${ua.substring(0, 500)}\`\`\``, inline: false }
  );
  
  // Parse User Agent for more details
  const uaLower = ua.toLowerCase();
  const osInfo = [];
  if (uaLower.includes('windows')) osInfo.push('Windows');
  if (uaLower.includes('mac')) osInfo.push('macOS');
  if (uaLower.includes('linux')) osInfo.push('Linux');
  if (uaLower.includes('android')) osInfo.push('Android');
  if (uaLower.includes('iphone') || uaLower.includes('ipad')) osInfo.push('iOS');
  
  const browserInfo = [];
  if (uaLower.includes('chrome') && !uaLower.includes('edg')) browserInfo.push('Chrome');
  if (uaLower.includes('firefox')) browserInfo.push('Firefox');
  if (uaLower.includes('safari') && !uaLower.includes('chrome')) browserInfo.push('Safari');
  if (uaLower.includes('edg')) browserInfo.push('Edge');
  if (uaLower.includes('opera')) browserInfo.push('Opera');
  
  if (osInfo.length > 0) {
    fields.push({ name: "🖥️ OS Detected", value: `\`${osInfo.join(', ')}\``, inline: true });
  }
  if (browserInfo.length > 0) {
    fields.push({ name: "🌍 Browser", value: `\`${browserInfo.join(', ')}\``, inline: true });
  }
  
  // Tool Detection Section
  if (toolInfo) {
    fields.push(
      { name: "━━━━━━━━━━━━━━━━━━━━", value: "⚠️ TOOL DETECTION", inline: false },
      { name: "🔨 Tool Name", value: `\`${toolInfo.tool.toUpperCase()}\``, inline: true },
      { name: "📊 Priority", value: `\`${toolInfo.priority}\``, inline: true },
      { name: "🏷️ Tool Type", value: `\`${toolInfo.type}\``, inline: true }
    );
  }
  
  // PIApi Intelligence Section (Detailed)
  if (piData) {
    fields.push({ name: "━━━━━━━━━━━━━━━━━━━━", value: "🛡️ IP INTELLIGENCE (PIApi)", inline: false });
    
    // Location Details
    if (piData.location) {
      const locationDetails = [];
      if (piData.location.city) locationDetails.push(`City: ${piData.location.city}`);
      if (piData.location.region) locationDetails.push(`Region: ${piData.location.region}`);
      if (piData.location.country) locationDetails.push(`Country: ${piData.location.country}`);
      if (piData.location.country_code) locationDetails.push(`Code: ${piData.location.country_code}`);
      if (piData.location.postal) locationDetails.push(`Postal: ${piData.location.postal}`);
      if (piData.location.latitude && piData.location.longitude) {
        locationDetails.push(`Coordinates: ${piData.location.latitude}, ${piData.location.longitude}`);
      }
      if (piData.location.timezone) locationDetails.push(`Timezone: ${piData.location.timezone}`);
      
      fields.push({
        name: "📍 Geolocation",
        value: `\`\`\`${locationDetails.join('\n')}\`\`\``,
        inline: false
      });
    }
    
    // ISP/ASN Details
    if (piData.company || piData.asn) {
      const ispDetails = [];
      if (piData.company?.name) ispDetails.push(`ISP: ${piData.company.name}`);
      if (piData.company?.domain) ispDetails.push(`Domain: ${piData.company.domain}`);
      if (piData.company?.type) ispDetails.push(`Type: ${piData.company.type}`);
      if (piData.asn?.asn) ispDetails.push(`ASN: ${piData.asn.asn}`);
      if (piData.asn?.org) ispDetails.push(`Organization: ${piData.asn.org}`);
      if (piData.asn?.route) ispDetails.push(`Route: ${piData.asn.route}`);
      if (piData.asn?.domain) ispDetails.push(`AS Domain: ${piData.asn.domain}`);
      
      fields.push({
        name: "🏢 ISP & ASN Information",
        value: `\`\`\`${ispDetails.join('\n')}\`\`\``,
        inline: false
      });
    }
    
    // Security Flags
    const securityFlags = [];
    securityFlags.push(`🔒 Datacenter: ${piData.is_datacenter ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 Proxy: ${piData.is_proxy ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 VPN: ${piData.is_vpn ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 TOR: ${piData.is_tor ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 Relay: ${piData.is_relay ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 Crawler: ${piData.is_crawler ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 Bot: ${piData.is_bot ? 'YES' : 'NO'}`);
    securityFlags.push(`🔒 Mobile: ${piData.is_mobile ? 'YES' : 'NO'}`);
    
    fields.push({
      name: "🚨 Security Flags",
      value: `\`\`\`${securityFlags.join('\n')}\`\`\``,
      inline: false
    });
    
    // Risk Score if available
    if (piData.risk_score !== undefined) {
      const riskLevel = piData.risk_score > 80 ? '🔴 CRITICAL' : piData.risk_score > 50 ? '🟠 HIGH' : piData.risk_score > 20 ? '🟡 MEDIUM' : '🟢 LOW';
      fields.push({
        name: "📊 Risk Assessment",
        value: `\`\`\`Score: ${piData.risk_score}/100\nLevel: ${riskLevel}\`\`\``,
        inline: false
      });
    }
    
    // Connection Type
    if (piData.connection) {
      fields.push({
        name: "🔌 Connection Type",
        value: `\`${piData.connection}\``,
        inline: true
      });
    }
    
    // Carrier Info (for mobile)
    if (piData.carrier) {
      fields.push({
        name: "📱 Carrier",
        value: `\`${piData.carrier.name || piData.carrier}\``,
        inline: true
      });
    }
  }
  
  // Additional Information
  if (additionalInfo.extra) {
    fields.push(
      { name: "━━━━━━━━━━━━━━━━━━━━", value: "📝 ADDITIONAL INFO", inline: false },
      { name: "Extra Data", value: `\`${additionalInfo.extra}\``, inline: false }
    );
  }
  
  // Headers Information (capture some useful headers)
  if (additionalInfo.headers) {
    const importantHeaders = [];
    if (additionalInfo.headers['accept-language']) importantHeaders.push(`Accept-Language: ${additionalInfo.headers['accept-language']}`);
    if (additionalInfo.headers['accept-encoding']) importantHeaders.push(`Accept-Encoding: ${additionalInfo.headers['accept-encoding']}`);
    if (additionalInfo.headers['sec-ch-ua']) importantHeaders.push(`Sec-CH-UA: ${additionalInfo.headers['sec-ch-ua']}`);
    if (additionalInfo.headers['sec-ch-ua-platform']) importantHeaders.push(`Platform: ${additionalInfo.headers['sec-ch-ua-platform']}`);
    
    if (importantHeaders.length > 0) {
      fields.push({
        name: "📨 Request Headers",
        value: `\`\`\`${importantHeaders.join('\n')}\`\`\``,
        inline: false
      });
    }
  }
  
  // Threat Category
  let threatCategory = "Unknown";
  if (toolInfo) threatCategory = "Tool/Scanner Detection";
  else if (piData?.is_proxy || piData?.is_vpn || piData?.is_tor) threatCategory = "Proxy/VPN/TOR Usage";
  else if (piData?.is_datacenter) threatCategory = "Datacenter/Hosting";
  else if (piData?.is_crawler) threatCategory = "Web Crawler/Bot";
  else if (reason.includes("failed")) threatCategory = "Failed Verification";
  
  fields.unshift({
    name: "⚠️ Threat Classification",
    value: `\`${threatCategory}\``,
    inline: false
  });
  
  // Build embed color based on threat severity
  let embedColor = 15158332; // Default red
  if (toolInfo?.priority === 'HIGH') embedColor = 15548997; // Bright red
  else if (piData?.risk_score > 80) embedColor = 15548997;
  else if (piData?.risk_score > 50) embedColor = 15158332;
  else if (piData?.risk_score > 20) embedColor = 15844367; // Orange
  
  const data = {
    username: "🛡️ Security Intelligence System",
    avatar_url: "https://vercel.com/favicon.ico",
    embeds: [{
      title: "🚨 SECURITY ALERT - Unauthorized Access Attempt",
      color: embedColor,
      fields: fields,
      footer: { 
        text: "PinatHub Security v8 • Real-time Threat Intelligence",
        icon_url: "https://vercel.com/favicon.ico"
      },
      timestamp: new Date().toISOString(),
      thumbnail: {
        url: "https://cdn-icons-png.flaticon.com/512/564/564619.png"
      }
    }]
  };

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    console.log(`[DISCORD] Log sent for IP ${ip}`);
  } catch (e) {
    console.error("Webhook error:", e);
  }
}

// Access Denied Page
function renderAccessDeniedPage(ip, reason, toolDetected = null, piData = null) {
  const toolMessage = toolDetected ? `🔧 Tool detected: ${toolDetected.tool.toUpperCase()}` : '';
  const proxyMessage = piData && detectProxyVpn(piData) ? `🚫 ${detectProxyVpn(piData)} DETECTED` : '';
  
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Access Denied</title>
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
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="badge">⚠️ ACCESS DENIED</div>
                <h1>403</h1>
                <h2 style="color: var(--geist-error);">Restricted Area</h2>
                <p>This resource is not available from your current location.</p>
                
                <div class="ip-box">
                    <strong>Your IP:</strong> ${ip}
                </div>
                
                ${toolMessage || proxyMessage ? `
                <div class="info-grid">
                    ${toolMessage ? `
                    <div class="info-item">
                        <div class="info-label">Detected Environment</div>
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
                        <div class="info-label">Reference ID</div>
                        <div class="info-value">${Math.random().toString(36).substring(2, 10)}</div>
                    </div>
                </div>
                ` : ''}
                
                <hr>
                
                <div class="footer">
                    incident_id: ${Math.random().toString(36).substring(2, 10)}<br>
                    status: restricted
                </div>
            </div>
        </div>
    </body>
    </html>
  `;
}

// Whitelist Game Hub (7 games)
function renderWhitelistGameHub(ip) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Game Hub - Playground</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-success: #0070f3; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; margin: 0; padding: 40px 20px; }
            .container { max-width: 1400px; margin: 0 auto; }
            .header { text-align: center; margin-bottom: 40px; }
            .badge-owner { display: inline-block; background: linear-gradient(135deg, #0070f3, #00c6ff); color: white; font-size: 12px; font-weight: 600; padding: 4px 12px; border-radius: 100px; margin-bottom: 16px; text-transform: uppercase; letter-spacing: 0.5px; }
            h1 { font-size: 48px; font-weight: 700; letter-spacing: -2px; margin-bottom: 8px; }
            .sub { color: var(--accents-3); font-size: 14px; }
            .games-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 24px; margin-bottom: 40px; }
            .game-card { border: 1px solid var(--accents-2); border-radius: 16px; padding: 28px 24px; background: var(--geist-background); transition: all 0.3s ease; cursor: pointer; }
            .game-card:hover { transform: translateY(-6px); box-shadow: 0 20px 40px rgba(0,0,0,0.1); border-color: var(--geist-success); }
            .game-icon { font-size: 52px; margin-bottom: 20px; }
            .game-title { font-size: 22px; font-weight: 600; margin-bottom: 10px; }
            .game-desc { color: var(--accents-3); font-size: 13px; margin-bottom: 20px; line-height: 1.5; }
            .play-btn { background: var(--geist-foreground); color: var(--geist-background); border: none; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 500; cursor: pointer; transition: opacity 0.2s; }
            .play-btn:hover { opacity: 0.8; }
            .game-area { border: 1px solid var(--accents-2); border-radius: 20px; padding: 40px; margin-top: 30px; background: linear-gradient(135deg, var(--accents-1) 0%, var(--geist-background) 100%); }
            .back-btn { background: var(--accents-2); border: none; padding: 8px 20px; border-radius: 8px; cursor: pointer; margin-bottom: 20px; font-size: 13px; }
            .back-btn:hover { background: var(--accents-3); color: white; }
            .ip-info { background: linear-gradient(135deg, #000, #1a1a1a); color: #0f0; padding: 12px 20px; border-radius: 12px; font-family: monospace; font-size: 12px; margin-top: 30px; text-align: center; border: 1px solid #333; }
            hr { border: none; border-top: 1px solid var(--accents-2); margin: 30px 0; }
            .footer { text-align: center; font-size: 11px; color: var(--accents-3); margin-top: 40px; }
            @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
            .fade-in { animation: fadeIn 0.4s ease; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <div class="badge-owner">🎮 PREMIUM ACCESS • WHITELISTED</div>
                <h1>✨ Game Hub</h1>
                <div class="sub">Welcome! IP: ${ip.substring(0, 12)}*** • Enjoy unlimited gameplay</div>
            </div>

            <div class="games-grid" id="gamesGrid">
                <div class="game-card" onclick="showGame('guess')">
                    <div class="game-icon">🎯</div>
                    <div class="game-title">Number Guesser</div>
                    <div class="game-desc">Guess the secret number between 1-100. Test your intuition!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('door')">
                    <div class="game-icon">🚪</div>
                    <div class="game-title">Mystery Doors</div>
                    <div class="game-desc">Choose the correct door to find the hidden treasure!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('typing')">
                    <div class="game-icon">⌨️</div>
                    <div class="game-title">Speed Typist</div>
                    <div class="game-desc">Type the displayed word as fast as you can!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('memory')">
                    <div class="game-icon">🧠</div>
                    <div class="game-title">Memory Match</div>
                    <div class="game-desc">Match the pairs and train your memory!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('reaction')">
                    <div class="game-icon">⚡</div>
                    <div class="game-title">Reaction Clicker</div>
                    <div class="game-desc">Click as fast as you can when the button turns green!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('riddle')">
                    <div class="game-icon">❓</div>
                    <div class="game-title">Riddle Master</div>
                    <div class="game-desc">Solve clever riddles and prove your wit!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
                <div class="game-card" onclick="showGame('color')">
                    <div class="game-icon">🎨</div>
                    <div class="game-title">Color Matcher</div>
                    <div class="game-desc">Match the color name with its actual color!</div>
                    <button class="play-btn">Play Now →</button>
                </div>
            </div>

            <div id="gameArea" class="game-area" style="display: none;"></div>

            <div class="ip-info">
                🔒 SECURE CONNECTION • All games available • No restrictions
            </div>
            <hr>
            <div class="footer">
                Game Hub v2.0 • Premium Access
            </div>
        </div>

        <script>
            let currentGame = null;
            let guessNumber = null;
            let guessAttempts = 0;
            let doorChoice = null;
            let memoryCards = [];
            let memoryFlipped = [];
            let memoryMatched = [];
            let reactionActive = false;
            let reactionTimeout = null;
            let reactionStartTime = null;
            let riddleIndex = 0;
            let riddleScore = 0;
            let colorTarget = null;
            let firstFlipped = null;
            let secondFlipped = null;
            let waitTimeout = null;
            
            const riddles = [
                { q: "What has keys but can't open locks?", a: "piano" },
                { q: "What gets wetter as it dries?", a: "towel" },
                { q: "What has to be broken before you can use it?", a: "egg" },
                { q: "I'm tall when I'm young and short when I'm old. What am I?", a: "candle" },
                { q: "What month of the year has 28 days?", a: "all of them" }
            ];
            
            const colors = [
                { name: "RED", color: "#ff0000" },
                { name: "BLUE", color: "#0000ff" },
                { name: "GREEN", color: "#00ff00" },
                { name: "YELLOW", color: "#ffff00" },
                { name: "PURPLE", color: "#800080" },
                { name: "ORANGE", color: "#ffa500" }
            ];

            function showGame(game) {
                currentGame = game;
                const gameArea = document.getElementById('gameArea');
                const gamesGrid = document.getElementById('gamesGrid');
                gameArea.style.display = 'block';
                gameArea.classList.add('fade-in');
                gamesGrid.style.display = 'none';
                
                if (game === 'guess') initGuessGame();
                else if (game === 'door') initDoorGame();
                else if (game === 'typing') initTypingGame();
                else if (game === 'memory') initMemoryGame();
                else if (game === 'reaction') initReactionGame();
                else if (game === 'riddle') initRiddleGame();
                else if (game === 'color') initColorGame();
            }
            
            function backToGames() {
                document.getElementById('gameArea').style.display = 'none';
                document.getElementById('gamesGrid').style.display = 'grid';
                if (reactionTimeout) clearTimeout(reactionTimeout);
            }
            
            function initGuessGame() {
                guessNumber = Math.floor(Math.random() * 100) + 1;
                guessAttempts = 0;
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">🎯</div>
                        <h2>Number Guesser</h2>
                        <p>Guess the number between 1 and 100</p>
                        <div style="margin: 30px 0;">
                            <input type="number" id="guessInput" placeholder="Enter your guess" style="padding: 12px; border: 1px solid #eaeaea; border-radius: 8px; width: 200px; margin-right: 10px;">
                            <button onclick="makeGuess()" style="padding: 12px 24px; background: #000; color: #fff; border: none; border-radius: 8px; cursor: pointer;">Guess</button>
                        </div>
                        <div id="guessResult"></div>
                        <div class="score" style="margin-top: 20px; font-size: 14px; color: #666;">Attempts: \${guessAttempts}</div>
                    </div>
                \`;
            }
            
            function makeGuess() {
                const input = document.getElementById('guessInput');
                const guess = parseInt(input.value);
                const resultDiv = document.getElementById('guessResult');
                
                if (isNaN(guess)) {
                    resultDiv.innerHTML = '❌ Please enter a valid number!';
                    return;
                }
                
                guessAttempts++;
                document.querySelector('.score').innerHTML = \`Attempts: \${guessAttempts}\`;
                
                if (guess === guessNumber) {
                    resultDiv.innerHTML = \`🎉 CORRECT! The number was \${guessNumber}! You won in \${guessAttempts} attempts! 🎉\`;
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => backToGames(), 2000);
                } else if (guess < guessNumber) {
                    resultDiv.innerHTML = '📈 Too low! Try a higher number.';
                } else {
                    resultDiv.innerHTML = '📉 Too high! Try a lower number.';
                }
                input.value = '';
            }
            
            function initDoorGame() {
                doorChoice = Math.floor(Math.random() * 3);
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">🚪</div>
                        <h2>Mystery Doors</h2>
                        <p>Behind one door lies treasure. Choose wisely!</p>
                        <div style="margin: 40px 0; display: flex; justify-content: center; gap: 20px; flex-wrap: wrap;">
                            <button onclick="chooseDoor(0)" style="padding: 40px 30px; font-size: 48px; background: #fafafa; border: 2px solid #eaeaea; border-radius: 12px; cursor: pointer; transition: all 0.2s;">🚪 1</button>
                            <button onclick="chooseDoor(1)" style="padding: 40px 30px; font-size: 48px; background: #fafafa; border: 2px solid #eaeaea; border-radius: 12px; cursor: pointer; transition: all 0.2s;">🚪 2</button>
                            <button onclick="chooseDoor(2)" style="padding: 40px 30px; font-size: 48px; background: #fafafa; border: 2px solid #eaeaea; border-radius: 12px; cursor: pointer; transition: all 0.2s;">🚪 3</button>
                        </div>
                        <div id="doorResult"></div>
                    </div>
                \`;
            }
            
            function chooseDoor(door) {
                const resultDiv = document.getElementById('doorResult');
                if (door === doorChoice) {
                    resultDiv.innerHTML = '🎉 YOU FOUND THE TREASURE! 🎉<br>✨ Congratulations! ✨';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => backToGames(), 2000);
                } else {
                    resultDiv.innerHTML = '💀 Empty door... Try again! 💀';
                    resultDiv.style.color = '#ff0000';
                    setTimeout(() => initDoorGame(), 1500);
                }
            }
            
            function initTypingGame() {
                const words = ["pineapple", "javascript", "developer", "security", "challenge", "keyboard", "typing", "speed"];
                const targetWord = words[Math.floor(Math.random() * words.length)];
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">⌨️</div>
                        <h2>Speed Typist</h2>
                        <p>Type the word below as fast as you can!</p>
                        <div style="background: #000; color: #0f0; padding: 20px; border-radius: 12px; font-family: monospace; font-size: 32px; margin: 30px auto; display: inline-block; letter-spacing: 2px;">\${targetWord}</div>
                        <div>
                            <input type="text" id="typingInput" placeholder="Type here..." style="padding: 12px; border: 1px solid #eaeaea; border-radius: 8px; width: 250px; margin-right: 10px;">
                            <button onclick="checkTyping('\${targetWord}')" style="padding: 12px 24px; background: #000; color: #fff; border: none; border-radius: 8px; cursor: pointer;">Submit</button>
                        </div>
                        <div id="typingResult" style="margin-top: 20px;"></div>
                    </div>
                \`;
            }
            
            function checkTyping(target) {
                const input = document.getElementById('typingInput');
                const resultDiv = document.getElementById('typingResult');
                if (input.value.toLowerCase() === target.toLowerCase()) {
                    resultDiv.innerHTML = '✅ PERFECT! Amazing speed! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => backToGames(), 1500);
                } else {
                    resultDiv.innerHTML = '❌ Not quite right. Try again!';
                    resultDiv.style.color = '#ff0000';
                    input.value = '';
                }
            }
            
            function initMemoryGame() {
                const items = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼'];
                memoryCards = [...items, ...items];
                for (let i = memoryCards.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [memoryCards[i], memoryCards[j]] = [memoryCards[j], memoryCards[i]];
                }
                memoryFlipped = new Array(16).fill(false);
                memoryMatched = new Array(16).fill(false);
                renderMemoryGame();
            }
            
            function renderMemoryGame() {
                let cardsHtml = '';
                for (let i = 0; i < memoryCards.length; i++) {
                    let display = '?';
                    if (memoryFlipped[i] || memoryMatched[i]) display = memoryCards[i];
                    cardsHtml += \`<button onclick="flipCard(\${i})" style="width: 70px; height: 70px; margin: 5px; font-size: 32px; background: \${memoryMatched[i] ? '#e0ffe0' : '#fafafa'}; border: 2px solid #eaeaea; border-radius: 12px; cursor: pointer; transition: all 0.2s;">\${display}</button>\`;
                }
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">🧠</div>
                        <h2>Memory Match</h2>
                        <p>Match all the pairs!</p>
                        <div style="margin: 30px 0; display: flex; flex-wrap: wrap; justify-content: center; max-width: 400px; margin: 30px auto;">\${cardsHtml}</div>
                        <div id="memoryResult"></div>
                    </div>
                \`;
            }
            
            function flipCard(index) {
                if (waitTimeout) return;
                if (memoryMatched[index]) return;
                if (memoryFlipped[index]) return;
                if (firstFlipped !== null && secondFlipped !== null) return;
                
                memoryFlipped[index] = true;
                
                if (firstFlipped === null) {
                    firstFlipped = index;
                } else if (secondFlipped === null && firstFlipped !== index) {
                    secondFlipped = index;
                    
                    if (memoryCards[firstFlipped] === memoryCards[secondFlipped]) {
                        memoryMatched[firstFlipped] = true;
                        memoryMatched[secondFlipped] = true;
                        firstFlipped = null;
                        secondFlipped = null;
                        renderMemoryGame();
                        
                        if (memoryMatched.every(m => m === true)) {
                            document.getElementById('memoryResult').innerHTML = '🎉 YOU WIN! Amazing memory! 🎉';
                            setTimeout(() => backToGames(), 2000);
                        }
                    } else {
                        waitTimeout = setTimeout(() => {
                            memoryFlipped[firstFlipped] = false;
                            memoryFlipped[secondFlipped] = false;
                            firstFlipped = null;
                            secondFlipped = null;
                            renderMemoryGame();
                            waitTimeout = null;
                        }, 800);
                        renderMemoryGame();
                    }
                }
                renderMemoryGame();
            }
            
            function initReactionGame() {
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">⚡</div>
                        <h2>Reaction Clicker</h2>
                        <p>Click as fast as you can when the button turns GREEN!</p>
                        <div style="margin: 40px 0;">
                            <button id="reactionBtn" onclick="handleReactionClick()" style="padding: 40px 60px; font-size: 24px; background: #ccc; border: none; border-radius: 16px; cursor: pointer; transition: all 0.2s;">Wait...</button>
                        </div>
                        <div id="reactionResult"></div>
                    </div>
                \`;
                startReactionTimer();
            }
            
            function startReactionTimer() {
                const btn = document.getElementById('reactionBtn');
                reactionActive = false;
                const delay = Math.random() * 3000 + 1000;
                reactionTimeout = setTimeout(() => {
                    if (btn) {
                        btn.style.background = '#00ff00';
                        btn.innerHTML = 'CLICK NOW!';
                        reactionActive = true;
                        reactionStartTime = Date.now();
                    }
                }, delay);
            }
            
            function handleReactionClick() {
                const resultDiv = document.getElementById('reactionResult');
                if (!reactionActive) {
                    resultDiv.innerHTML = '❌ Too early! Wait for the green button.';
                    resultDiv.style.color = '#ff0000';
                    clearTimeout(reactionTimeout);
                    setTimeout(() => initReactionGame(), 1000);
                } else {
                    const reactionTime = Date.now() - reactionStartTime;
                    resultDiv.innerHTML = \`✅ \${reactionTime}ms! Great reaction! 🎉\`;
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => backToGames(), 1500);
                }
            }
            
            function initRiddleGame() {
                riddleIndex = 0;
                riddleScore = 0;
                showRiddle();
            }
            
            function showRiddle() {
                if (riddleIndex >= riddles.length) {
                    document.getElementById('gameArea').innerHTML = \`
                        <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                        <div style="text-align: center;">
                            <div class="game-icon" style="font-size: 48px;">🏆</div>
                            <h2>Riddle Master Complete!</h2>
                            <p>You solved all \${riddles.length} riddles! Score: \${riddleScore}/\${riddles.length}</p>
                            <div class="score" style="margin-top: 30px; font-size: 32px;">✨ Genius! ✨</div>
                        </div>
                    \`;
                    setTimeout(() => backToGames(), 3000);
                    return;
                }
                
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">❓</div>
                        <h2>Riddle \${riddleIndex + 1}/\${riddles.length}</h2>
                        <p style="font-size: 20px; margin: 30px 0;">\${riddles[riddleIndex].q}</p>
                        <div>
                            <input type="text" id="riddleInput" placeholder="Your answer..." style="padding: 12px; border: 1px solid #eaeaea; border-radius: 8px; width: 250px; margin-right: 10px;">
                            <button onclick="checkRiddle()" style="padding: 12px 24px; background: #000; color: #fff; border: none; border-radius: 8px; cursor: pointer;">Submit</button>
                        </div>
                        <div id="riddleResult" style="margin-top: 20px;"></div>
                        <div class="score" style="margin-top: 20px;">Score: \${riddleScore}/\${riddles.length}</div>
                    </div>
                \`;
            }
            
            function checkRiddle() {
                const input = document.getElementById('riddleInput');
                const resultDiv = document.getElementById('riddleResult');
                if (input.value.toLowerCase().trim() === riddles[riddleIndex].a) {
                    riddleScore++;
                    resultDiv.innerHTML = '✅ Correct!';
                    resultDiv.style.color = '#0070f3';
                    riddleIndex++;
                    setTimeout(() => showRiddle(), 1000);
                } else {
                    resultDiv.innerHTML = \`❌ Wrong! The answer was: \${riddles[riddleIndex].a}\`;
                    resultDiv.style.color = '#ff0000';
                    riddleIndex++;
                    setTimeout(() => showRiddle(), 1500);
                }
            }
            
            function initColorGame() {
                colorTarget = colors[Math.floor(Math.random() * colors.length)];
                const wrongColors = colors.filter(c => c.name !== colorTarget.name);
                const options = [colorTarget, ...wrongColors.slice(0, 3)];
                for (let i = options.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [options[i], options[j]] = [options[j], options[i]];
                }
                
                let optionsHtml = '';
                for (let opt of options) {
                    optionsHtml += \`<button onclick="checkColor('\${opt.name}')" style="background: \${opt.color}; width: 120px; height: 80px; margin: 10px; border: none; border-radius: 12px; cursor: pointer; color: white; font-weight: bold; text-shadow: 1px 1px 0 #000;">\${opt.name}</button>\`;
                }
                
                document.getElementById('gameArea').innerHTML = \`
                    <button class="back-btn" onclick="backToGames()">← Back to Games</button>
                    <div style="text-align: center;">
                        <div class="game-icon" style="font-size: 48px;">🎨</div>
                        <h2>Color Matcher</h2>
                        <p>Select the button that matches the color name BELOW:</p>
                        <div style="background: \${colorTarget.color}; padding: 40px; margin: 30px auto; border-radius: 16px; display: inline-block; min-width: 200px;">
                            <span style="font-size: 32px; font-weight: bold; color: white; text-shadow: 2px 2px 0 #000;">\${colorTarget.name}</span>
                        </div>
                        <div style="display: flex; justify-content: center; flex-wrap: wrap;">\${optionsHtml}</div>
                        <div id="colorResult" style="margin-top: 20px;"></div>
                    </div>
                \`;
            }
            
            function checkColor(selectedName) {
                const resultDiv = document.getElementById('colorResult');
                if (selectedName === colorTarget.name) {
                    resultDiv.innerHTML = '✅ CORRECT! Great eye! 🎉';
                    resultDiv.style.color = '#0070f3';
                    setTimeout(() => backToGames(), 1500);
                } else {
                    resultDiv.innerHTML = '❌ Wrong match! Try again!';
                    resultDiv.style.color = '#ff0000';
                    setTimeout(() => initColorGame(), 1000);
                }
            }
            
            window.makeGuess = makeGuess;
            window.chooseDoor = chooseDoor;
            window.checkTyping = checkTyping;
            window.flipCard = flipCard;
            window.handleReactionClick = handleReactionClick;
            window.checkRiddle = checkRiddle;
            window.checkColor = checkColor;
        </script>
    </body>
    </html>
  `;
}

// Main Game Challenge for regular visitors
function renderGameChallenge(ip) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Verification Challenge</title>
        <style>
            :root { --geist-foreground: #000; --geist-background: #fff; --accents-1: #fafafa; --accents-2: #eaeaea; --accents-3: #999; --geist-success: #0070f3; }
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: var(--geist-background); color: var(--geist-foreground); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; padding: 20px; }
            .container { max-width: 700px; width: 100%; }
            .card { border: 1px solid var(--accents-2); border-radius: 20px; padding: 40px 32px; background: var(--geist-background); box-shadow: 0 20px 40px rgba(0,0,0,0.05); }
            .step { font-size: 12px; color: var(--accents-3); margin-bottom: 16px; text-transform: uppercase; letter-spacing: 2px; }
            h1 { font-size: 28px; font-weight: 600; margin-bottom: 12px; letter-spacing: -0.02em; }
            .subtext { color: var(--accents-3); font-size: 14px; line-height: 1.6; margin-bottom: 28px; }
            .game-selector { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 20px 0; }
            .game-btn { padding: 16px; background: var(--geist-background); border: 1px solid var(--accents-2); border-radius: 12px; font-size: 14px; cursor: pointer; transition: all 0.2s; text-align: center; }
            .game-btn:hover { border-color: var(--geist-foreground); transform: translateY(-2px); background: var(--accents-1); }
            .game-icon { font-size: 32px; margin-bottom: 8px; }
            .active-game { margin-top: 30px; padding-top: 30px; border-top: 1px solid var(--accents-2); }
            .input-field { padding: 12px; border: 1px solid var(--accents-2); border-radius: 8px; font-size: 14px; width: 100%; margin: 10px 0; }
            .submit-btn { background: var(--geist-foreground); color: var(--geist-background); border: none; padding: 12px 24px; border-radius: 8px; font-size: 14px; cursor: pointer; transition: opacity 0.2s; }
            .submit-btn:hover { opacity: 0.8; }
            .message { margin-top: 15px; font-size: 14px; }
            .success { color: var(--geist-success); }
            .error { color: #ff0000; }
            .vercel-icon { margin-bottom: 24px; }
            .footer-text { font-size: 11px; color: var(--accents-3); text-align: center; margin-top: 30px; }
            @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <div class="vercel-icon">
                    <svg width="25" height="22" viewBox="0 0 76 65" fill="currentColor"><path d="M37.5274 0L75.0548 65H0L37.5274 0Z"/></svg>
                </div>
                
                <div class="step">VERIFICATION CHALLENGE</div>
                <h1>🎮 Welcome!</h1>
                <div class="subtext">Complete any game below to continue. Have fun!</div>
                
                <div class="game-selector">
                    <div class="game-btn" onclick="startGame('guess')">
                        <div class="game-icon">🎯</div>
                        <div>Number Guesser</div>
                    </div>
                    <div class="game-btn" onclick="startGame('door')">
                        <div class="game-icon">🚪</div>
                        <div>Mystery Doors</div>
                    </div>
                    <div class="game-btn" onclick="startGame('typing')">
                        <div class="game-icon">⌨️</div>
                        <div>Speed Typist</div>
                    </div>
                    <div class="game-btn" onclick="startGame('memory')">
                        <div class="game-icon">🧠</div>
                        <div>Memory Match</div>
                    </div>
                    <div class="game-btn" onclick="startGame('reaction')">
                        <div class="game-icon">⚡</div>
                        <div>Reaction Clicker</div>
                    </div>
                    <div class="game-btn" onclick="startGame('riddle')">
                        <div class="game-icon">❓</div>
                        <div>Riddle Master</div>
                    </div>
                    <div class="game-btn" onclick="startGame('color')">
                        <div class="game-icon">🎨</div>
                        <div>Color Matcher</div>
                    </div>
                </div>
                
                <div id="activeGame" class="active-game" style="display: none;"></div>
                
                <div class="footer-text">
                    protected by security system • complete any game to proceed
                </div>
            </div>
        </div>

        <script>
            let currentGame = null;
            let guessNumber = null;
            let guessAttempts = 0;
            let doorChoice = null;
            let memoryCards = [];
            let memoryFlipped = [];
            let memoryMatched = [];
            let reactionActive = false;
            let reactionTimeout = null;
            let reactionStartTime = null;
            let riddleIndex = 0;
            let riddleScore = 0;
            let colorTarget = null;
            let firstFlipped = null;
            let secondFlipped = null;
            let waitTimeout = null;
            
            const riddles = [
                { q: "What has keys but can't open locks?", a: "piano" },
                { q: "What gets wetter as it dries?", a: "towel" },
                { q: "What has to be broken before you can use it?", a: "egg" },
                { q: "I'm tall when I'm young and short when I'm old. What am I?", a: "candle" }
            ];
            
            const colors = [
                { name: "RED", color: "#ff0000" },
                { name: "BLUE", color: "#0000ff" },
                { name: "GREEN", color: "#00ff00" },
                { name: "YELLOW", color: "#ffff00" }
            ];
            
            function startGame(game) {
                currentGame = game;
                const activeDiv = document.getElementById('activeGame');
                activeDiv.style.display = 'block';
                
                if (game === 'guess') {
                    guessNumber = Math.floor(Math.random() * 100) + 1;
                    guessAttempts = 0;
                    activeDiv.innerHTML = \`
                        <h3>🎯 Number Guesser</h3>
                        <p>Guess the number between 1-100</p>
                        <input type="number" id="guessInput" class="input-field" placeholder="Enter your guess">
                        <button class="submit-btn" onclick="handleGuess()">Submit Guess</button>
                        <div id="guessMessage" class="message"></div>
                        <div style="font-size: 12px; color: #666; margin-top: 10px;">Attempts: \${guessAttempts}</div>
                    \`;
                } else if (game === 'door') {
                    doorChoice = Math.floor(Math.random() * 3);
                    activeDiv.innerHTML = \`
                        <h3>🚪 Mystery Doors</h3>
                        <p>Choose the door with the treasure!</p>
                        <div style="display: flex; gap: 15px; margin: 20px 0;">
                            <button class="submit-btn" onclick="chooseDoor(0)" style="font-size: 30px; padding: 20px;">🚪 1</button>
                            <button class="submit-btn" onclick="chooseDoor(1)" style="font-size: 30px; padding: 20px;">🚪 2</button>
                            <button class="submit-btn" onclick="chooseDoor(2)" style="font-size: 30px; padding: 20px;">🚪 3</button>
                        </div>
                        <div id="doorMessage" class="message"></div>
                    \`;
                } else if (game === 'typing') {
                    const words = ["developer", "security", "challenge", "keyboard"];
                    const target = words[Math.floor(Math.random() * words.length)];
                    activeDiv.innerHTML = \`
                        <h3>⌨️ Speed Typist</h3>
                        <div style="background: #000; color: #0f0; padding: 15px; border-radius: 8px; font-family: monospace; font-size: 24px; margin: 15px 0; text-align: center;">\${target}</div>
                        <input type="text" id="typingInput" class="input-field" placeholder="Type the word above">
                        <button class="submit-btn" onclick="handleTyping('\${target}')">Submit</button>
                        <div id="typingMessage" class="message"></div>
                    \`;
                } else if (game === 'memory') {
                    const items = ['🐶', '🐱', '🐭', '🐹'];
                    memoryCards = [...items, ...items];
                    for (let i = memoryCards.length - 1; i > 0; i--) {
                        const j = Math.floor(Math.random() * (i + 1));
                        [memoryCards[i], memoryCards[j]] = [memoryCards[j], memoryCards[i]];
                    }
                    memoryFlipped = new Array(8).fill(false);
                    memoryMatched = new Array(8).fill(false);
                    renderMemoryGame();
                } else if (game === 'reaction') {
                    activeDiv.innerHTML = \`
                        <h3>⚡ Reaction Clicker</h3>
                        <p>Click when the button turns GREEN!</p>
                        <button id="reactionBtn" onclick="handleReaction()" style="padding: 30px 50px; font-size: 20px; background: #ccc; border: none; border-radius: 12px; cursor: pointer; margin: 20px 0;">Wait...</button>
                        <div id="reactionMessage" class="message"></div>
                    \`;
                    startReactionTimer();
                } else if (game === 'riddle') {
                    riddleIndex = 0;
                    riddleScore = 0;
                    showRiddle();
                } else if (game === 'color') {
                    initColorGame();
                }
            }
            
            function handleGuess() {
                const input = document.getElementById('guessInput');
                const guess = parseInt(input.value);
                const msg = document.getElementById('guessMessage');
                
                if (isNaN(guess)) {
                    msg.innerHTML = '❌ Please enter a valid number!';
                    msg.className = 'message error';
                    return;
                }
                
                guessAttempts++;
                document.querySelector('#activeGame div:last-child').innerHTML = \`Attempts: \${guessAttempts}\`;
                
                if (guess === guessNumber) {
                    msg.innerHTML = \`🎉 CORRECT! The number was \${guessNumber}! You win! 🎉\`;
                    msg.className = 'message success';
                    setTimeout(() => completeChallenge(), 1500);
                } else if (guess < guessNumber) {
                    msg.innerHTML = '📈 Too low! Try a higher number.';
                    msg.className = 'message error';
                } else {
                    msg.innerHTML = '📉 Too high! Try a lower number.';
                    msg.className = 'message error';
                }
                input.value = '';
            }
            
            function chooseDoor(door) {
                const msg = document.getElementById('doorMessage');
                if (door === doorChoice) {
                    msg.innerHTML = '🎉 YOU FOUND THE TREASURE! 🎉';
                    msg.className = 'message success';
                    setTimeout(() => completeChallenge(), 1500);
                } else {
                    msg.innerHTML = '💀 Empty door... Try again! 💀';
                    msg.className = 'message error';
                    setTimeout(() => startGame('door'), 1000);
                }
            }
            
            function handleTyping(target) {
                const input = document.getElementById('typingInput');
                const msg = document.getElementById('typingMessage');
                if (input.value.toLowerCase() === target.toLowerCase()) {
                    msg.innerHTML = '✅ PERFECT! You passed! 🎉';
                    msg.className = 'message success';
                    setTimeout(() => completeChallenge(), 1500);
                } else {
                    msg.innerHTML = '❌ Not quite right. Try again!';
                    msg.className = 'message error';
                    input.value = '';
                }
            }
            
            function renderMemoryGame() {
                let cardsHtml = '';
                for (let i = 0; i < memoryCards.length; i++) {
                    let display = '?';
                    if (memoryFlipped[i] || memoryMatched[i]) display = memoryCards[i];
                    cardsHtml += \`<button onclick="flipCard(\${i})" style="width: 60px; height: 60px; margin: 5px; font-size: 28px; background: \${memoryMatched[i] ? '#e0ffe0' : '#fafafa'}; border: 2px solid #eaeaea; border-radius: 10px; cursor: pointer;">\${display}</button>\`;
                }
                document.getElementById('activeGame').innerHTML = \`
                    <h3>🧠 Memory Match</h3>
                    <p>Match all the pairs!</p>
                    <div style="display: flex; flex-wrap: wrap; justify-content: center; max-width: 300px; margin: 20px auto;">\${cardsHtml}</div>
                    <div id="memoryMessage" class="message"></div>
                \`;
            }
            
            function flipCard(index) {
                if (waitTimeout) return;
                if (memoryMatched[index]) return;
                if (memoryFlipped[index]) return;
                if (firstFlipped !== null && secondFlipped !== null) return;
                
                memoryFlipped[index] = true;
                
                if (firstFlipped === null) {
                    firstFlipped = index;
                } else if (secondFlipped === null && firstFlipped !== index) {
                    secondFlipped = index;
                    
                    if (memoryCards[firstFlipped] === memoryCards[secondFlipped]) {
                        memoryMatched[firstFlipped] = true;
                        memoryMatched[secondFlipped] = true;
                        firstFlipped = null;
                        secondFlipped = null;
                        renderMemoryGame();
                        
                        if (memoryMatched.every(m => m === true)) {
                            document.getElementById('memoryMessage').innerHTML = '🎉 YOU WIN! 🎉';
                            document.getElementById('memoryMessage').className = 'message success';
                            setTimeout(() => completeChallenge(), 1500);
                        }
                    } else {
                        waitTimeout = setTimeout(() => {
                            memoryFlipped[firstFlipped] = false;
                            memoryFlipped[secondFlipped] = false;
                            firstFlipped = null;
                            secondFlipped = null;
                            renderMemoryGame();
                            waitTimeout = null;
                        }, 800);
                        renderMemoryGame();
                    }
                }
                renderMemoryGame();
            }
            
            function startReactionTimer() {
                const btn = document.getElementById('reactionBtn');
                reactionActive = false;
                const delay = Math.random() * 3000 + 1000;
                reactionTimeout = setTimeout(() => {
                    if (btn) {
                        btn.style.background = '#00ff00';
                        btn.innerHTML = 'CLICK NOW!';
                        reactionActive = true;
                        reactionStartTime = Date.now();
                    }
                }, delay);
            }
            
            function handleReaction() {
                const msg = document.getElementById('reactionMessage');
                if (!reactionActive) {
                    msg.innerHTML = '❌ Too early! Wait for green.';
                    msg.className = 'message error';
                    clearTimeout(reactionTimeout);
                    setTimeout(() => startGame('reaction'), 1000);
                } else {
                    const time = Date.now() - reactionStartTime;
                    msg.innerHTML = \`✅ \${time}ms! Great reaction! 🎉\`;
                    msg.className = 'message success';
                    setTimeout(() => completeChallenge(), 1500);
                }
            }
            
            function showRiddle() {
                if (riddleIndex >= riddles.length) {
                    document.getElementById('activeGame').innerHTML = \`
                        <h3>🏆 Riddle Master Complete!</h3>
                        <p>You solved all riddles!</p>
                        <div class="message success" style="margin-top: 20px;">✨ Genius! ✨</div>
                    \`;
                    setTimeout(() => completeChallenge(), 1500);
                    return;
                }
                
                document.getElementById('activeGame').innerHTML = \`
                    <h3>❓ Riddle \${riddleIndex + 1}/\${riddles.length}</h3>
                    <p style="font-size: 18px; margin: 20px 0;">\${riddles[riddleIndex].q}</p>
                    <input type="text" id="riddleInput" class="input-field" placeholder="Your answer">
                    <button class="submit-btn" onclick="checkRiddle()">Submit</button>
                    <div id="riddleMessage" class="message"></div>
                    <div style="font-size: 12px; color: #666; margin-top: 10px;">Score: \${riddleScore}/\${riddles.length}</div>
                \`;
            }
            
            function checkRiddle() {
                const input = document.getElementById('riddleInput');
                const msg = document.getElementById('riddleMessage');
                if (input.value.toLowerCase().trim() === riddles[riddleIndex].a) {
                    riddleScore++;
                    msg.innerHTML = '✅ Correct!';
                    msg.className = 'message success';
                    riddleIndex++;
                    setTimeout(() => showRiddle(), 1000);
                } else {
                    msg.innerHTML = \`❌ Wrong! The answer is: \${riddles[riddleIndex].a}\`;
                    msg.className = 'message error';
                    riddleIndex++;
                    setTimeout(() => showRiddle(), 1500);
                }
            }
            
            function initColorGame() {
                colorTarget = colors[Math.floor(Math.random() * colors.length)];
                const wrongColors = colors.filter(c => c.name !== colorTarget.name);
                const options = [colorTarget, ...wrongColors.slice(0, 3)];
                for (let i = options.length - 1; i > 0; i--) {
                    const j = Math.floor(Math.random() * (i + 1));
                    [options[i], options[j]] = [options[j], options[i]];
                }
                
                let optionsHtml = '';
                for (let opt of options) {
                    optionsHtml += \`<button onclick="checkColor('\${opt.name}')" style="background: \${opt.color}; padding: 15px 25px; margin: 5px; border: none; border-radius: 8px; cursor: pointer; color: white; font-weight: bold;">\${opt.name}</button>\`;
                }
                
                document.getElementById('activeGame').innerHTML = \`
                    <h3>🎨 Color Matcher</h3>
                    <div style="background: \${colorTarget.color}; padding: 30px; margin: 20px auto; border-radius: 12px; display: inline-block; width: 100%;">
                        <span style="font-size: 28px; font-weight: bold; color: white; text-shadow: 1px 1px 0 #000;">\${colorTarget.name}</span>
                    </div>
                    <div>\${optionsHtml}</div>
                    <div id="colorMessage" class="message"></div>
                \`;
            }
            
            function checkColor(selectedName) {
                const msg = document.getElementById('colorMessage');
                if (selectedName === colorTarget.name) {
                    msg.innerHTML = '✅ CORRECT! 🎉';
                    msg.className = 'message success';
                    setTimeout(() => completeChallenge(), 1500);
                } else {
                    msg.innerHTML = '❌ Wrong! Try again!';
                    msg.className = 'message error';
                    setTimeout(() => initColorGame(), 1000);
                }
            }
            
            async function completeChallenge() {
                await fetch(window.location.href, { method: 'POST' });
                window.location.reload();
            }
            
            window.handleGuess = handleGuess;
            window.chooseDoor = chooseDoor;
            window.handleTyping = handleTyping;
            window.flipCard = flipCard;
            window.handleReaction = handleReaction;
            window.checkRiddle = checkRiddle;
            window.checkColor = checkColor;
        </script>
    </body>
    </html>
  `;
}

// MAIN HANDLER
export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const ip = getRealIP(req);
  
  // Capture headers for Discord log
  const headers = {
    'accept-language': req.headers['accept-language'],
    'accept-encoding': req.headers['accept-encoding'],
    'sec-ch-ua': req.headers['sec-ch-ua'],
    'sec-ch-ua-platform': req.headers['sec-ch-ua-platform'],
    'referer': req.headers['referer'],
    'origin': req.headers['origin']
  };
  
  // Check whitelist first
  if (isWhitelisted(ip)) {
    console.log(`[WHITELIST] IP ${ip} - Full access granted`);
    
    if (userAgent.includes('roblox') && !userAgent.includes('robloxstudio')) {
      try {
        const response = await fetch('https://pinatbladeball-peotect.vercel.app/api/script.js');
        const content = await response.text();
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        return res.status(200).send(content);
      } catch (err) {
        return res.status(500).send('-- [error]: source offline.');
      }
    }
    
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderWhitelistGameHub(ip));
  }
  
  // Roblox bypass
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');
  
  if (isRoblox) {
    try {
      const response = await fetch('https://pinatbladeball-peotect.vercel.app/api/script.js');
      const content = await response.text();
      res.setHeader('Content-Type', 'text/plain');
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      return res.status(200).send(content);
    } catch (err) {
      return res.status(500).send('-- [error]: source offline.');
    }
  }
  
  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('restricted_ips');
    
    // Check if IP is restricted
    const blocked = await blacklist.findOne({ ip: ip });
    if (blocked) {
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderAccessDeniedPage(ip, blocked.reason, blocked.toolInfo, blocked.piData));
    }
    
    // Get PIApi data
    const piData = await getPiApiData(ip);
    
    // Detect proxy/VPN
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
      
      // Send comprehensive Discord log with all details
      await sendDiscordLog(ip, `Proxy/VPN Detected: ${proxyVpnDetect}`, userAgent, null, piData, { 
        extra: `Blocked for using ${proxyVpnDetect}`,
        headers: headers
      });
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderAccessDeniedPage(ip, `Proxy/VPN Detected: ${proxyVpnDetect}`, null, piData));
    }
    
    // Detect forbidden tools
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
      
      // Send comprehensive Discord log with tool details
      await sendDiscordLog(ip, `Illegal Tool: ${detectedTool.tool}`, userAgent, detectedTool, piData, {
        extra: `Tool type: ${detectedTool.type}, Priority: ${detectedTool.priority}`,
        headers: headers
      });
      
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderAccessDeniedPage(ip, `Tool detected: ${detectedTool.tool}`, detectedTool, piData));
    }
    
    // For browsers, show game challenge
    if (req.method === 'POST') {
      await blacklist.insertOne({ 
        ip: ip, 
        reason: 'failed_challenge', 
        date: new Date(),
        piData: piData,
        userAgent: userAgent
      });
      
      // Send Discord log for failed challenge
      await sendDiscordLog(ip, "Failed Verification Challenge", userAgent, null, piData, {
        extra: "User failed to complete any game challenge",
        headers: headers
      });
      
      return res.status(200).json({ status: 'restricted' });
    }
    
    // Show game challenge page
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(renderGameChallenge(ip));
    
  } catch (err) {
    console.error("Handler error:", err);
    return res.status(500).send('-- [error]: internal server error.');
  } finally {
    await client.close();
  }
}
