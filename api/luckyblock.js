import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

// --- CONFIGURATION: WHITELISTED IPs ---
// These IPs will bypass all security checks (Blacklist & Tool Detection)
const WHITELISTED_IPS = [
    '202.58.78.13', 
    // You can add other IPs here if needed
];

// --- CONFIGURATION: DISCORD LOGGING ---
async function sendDiscordLog(ip, reason, ua, tool) {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  try {
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username: "PinatHub Security",
        avatar_url: "https://files.catbox.moe/s6agav.png",
        embeds: [{
          title: "⚠️ PERMANENT BLACKLIST TRIGGERED",
          color: 9838400, // Dark Red
          fields: [
            { name: "🚫 IP Address", value: `\`${ip}\``, inline: true },
            { name: "🔍 Threat", value: `\`${tool || 'Unknown'}\``, inline: true },
            { name: "📝 Reason", value: `\`${reason}\``, inline: false },
            { name: "🕵️ User Agent", value: `\`\`\`${ua.substring(0, 150)}\`\`\`` }
          ],
          footer: { text: "PinatHub Guard • Zero Tolerance" },
          timestamp: new Date()
        }]
      })
    });
  } catch (e) { console.error("Discord Log Error:", e); }
}

// --- PAGE: BLACKLIST SCREEN ---
function renderBlacklist(ip, reason, tool) {
  return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Security Alert • PinatHub</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <style>body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }</style>
    </head>
    <body class="bg-[#050505] text-[#ededed] flex items-center justify-center min-h-screen p-4">
        <div class="w-full max-w-md bg-[#111] border border-[#333] rounded-xl p-8 shadow-2xl text-center relative overflow-hidden">
            <div class="absolute top-0 left-1/2 -translate-x-1/2 w-full h-1 bg-gradient-to-r from-transparent via-red-600 to-transparent opacity-50"></div>
            
            <div class="mb-6 flex justify-center">
                <div class="w-16 h-16 rounded-full bg-red-900/10 flex items-center justify-center text-red-500 border border-red-900/30">
                    <svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                </div>
            </div>
            
            <h1 class="text-2xl font-bold text-white mb-2 tracking-tight">Access Denied</h1>
            <p class="text-zinc-400 text-sm mb-6 leading-relaxed">
                Our security system has detected malicious activity originating from your device.
                <br>Your IP has been <span class="text-red-400 font-semibold">Permanently Blacklisted</span>.
            </p>

            <div class="bg-[#0a0a0a] rounded-lg p-4 border border-[#222] text-left mb-6 text-sm font-mono space-y-2">
                <div class="flex justify-between text-zinc-500">
                    <span>Target IP:</span>
                    <span class="text-zinc-300">${ip}</span>
                </div>
                <div class="flex justify-between text-zinc-500">
                    <span>Threat:</span>
                    <span class="text-red-400">${tool || 'Suspicious Pattern'}</span>
                </div>
                <div class="flex justify-between text-zinc-500">
                    <span>Reason:</span>
                    <span class="text-red-400 break-all">${reason}</span>
                </div>
            </div>

            <p class="text-xs text-zinc-600 uppercase tracking-widest">PinatHub Security Layer v4.0</p>
        </div>
    </body>
    </html>
  `;
}

// --- LOGIC: STRICT TOOL DETECTION (200+ PATTERNS) ---
function isMaliciousTool(userAgent) {
  if (!userAgent || userAgent.length < 15) return { isMalicious: true, reason: 'Empty/Invalid UA', tool: 'Unknown' };
  
  const ua = userAgent.toLowerCase();
  
  const maliciousPatterns = [
    // HTTP Clients & Downloaders
    'curl', 'wget', 'aria2', 'axel', 'httrack', 'httpie', 'postman', 'insomnia', 'bruno', 'swagger', 
    'openapi', 'graphql', 'python-requests', 'aiohttp', 'httpx', 'urllib', 'pycurl', 'scrapy', 'beautifulsoup',
    'mechanize', 'selenium', 'puppeteer', 'playwright', 'phantomjs', 'headless', 'chrome-headless', 'webkit',
    'geckodriver', 'chromedriver', 'node-fetch', 'axios', 'superagent', 'got', 'undici', 'request', 'http',
    'https', 'curl/', 'wget/', 'libwww-perl', 'lwp-trivial', 'libcurl', 'winhttp',
    
    // Programming Languages & Runtimes
    'python', 'java/', 'jdk', 'jre', 'ruby', 'perl', 'php', 'golang', 'go-http', 'rust', 'curl/', 'node', 
    'npm/', 'yarn/', 'pip/', 'maven', 'gradle', 'composer', 'nuget', 'cargo', 'go-', 'dart/',
    
    // Pentest & Security Tools
    'nmap', 'masscan', 'zmap', 'gobuster', 'dirb', 'dirbuster', 'wfuzz', 'ffuf', 'nikto', 'wapiti', 'zap', 
    'burp', 'sqlmap', 'hydra', 'medusa', 'john', 'hashcat', 'metasploit', 'beef', 'xsser', 'commix', 
    'dnsrecon', 'theharvester', 'recon-ng', 'sn1per', 'autosploit', 'shodan', 'censys', 'binaryedge',
    
    // Bots & Spiders
    'bot', 'spider', 'crawler', 'scraper', 'scraping', 'crawl', 'slurp', 'spider', 'curl', 'wget', 
    'python-urllib', 'libwww', 'lwp::simple', 'httpunit', 'htmlunit', 'jakarta', 'pippo', 'grub',
    'architextspider', 'xenu', 'zeus', 'checkbot', 'linkbot', 'linkwalker', 'scooter', 'mercator',
    'validator', 'webcopier', 'webzip', 'offline', 'teleport', 'webstrip', 'webmirror', 'webspider',
    'webbandit', 'webmasterworld', 'webwatch', 'webwombat', 'wget', 'linkextractorpro', 'linkscan',
    'msiecrawler', 'netscape', 'microsoft internet explorer', 'internet explore', 'mozilla/', 'gecko/',
    'trident/', 'webkit/', 'presto/', 'khtml/', 'browsex', 'amaya', 'amigavoyager', 'amiga-aweb',
    'bison', 'camino', 'chimera', 'cyberdog', 'dillo', 'docomo', 'dreamcast', 'ecatch', 'elinks',
    'emacs-w3', 'ewbrowser', 'galeon', 'ibrowse', 'icab', 'konqueror', 'links', 'lynx', 'omniweb',
    'opera', 'oregano', 'safari', 'voyager', 'w3m', 'curl', 'wget', 'python', 'java', 'perl', 'php',
    
    // Suspicious Headers/Proxies
    'vpn', 'proxy', 'tor/', 'tord', 'vps', 'hosting', 'cloud', 'server', 'scan', 'audit', 'test',
    'monitor', 'check', 'health', 'ping', 'trace', 'route', 'whois', 'dig', 'nslookup', 'bind',
    
    // Libraries often used for scraping
    'cheerio', 'jsdom', 'axios', 'superagent', 'request-promise', 'node-superfetch', 'node-fetch',
    'unirest', 'fetch-api', 'restsharp', 'resteasy', 'retrofit', 'volley', 'okhttp', 'asynchttpclient',
    'httpurlconnection', 'httpclient', 'webclient', 'resttemplate', 'feign', 'axis', 'cxf', 'jaxrs',
    
    // Mobile & Others
    'okhttp', 'dart:io', 'java/', 'dalvik/', 'linux', 'android', 'iphone', 'ipad', 'ipod', 'windows',
    'macintosh', 'mac os x', 'x11', 'ubuntu', 'debian', 'fedora', 'centos', 'red hat', 'suse',
    'mandriva', 'gentoo', 'slackware', 'arch', 'freebsd', 'openbsd', 'netbsd', 'sunos', 'solaris',
    'hp-ux', 'aix', 'irix', 'os/2', 'amigaos', 'morphos', 'risc os', 'syllable', 'beos', 'haiku',
    'qnx', 'vms', 'z/os', 'os/400', 'dos', 'windows 95', 'windows 98', 'windows nt', 'windows 2000',
    'windows xp', 'windows vista', 'windows 7', 'windows 8', 'windows 10', 'windows 11', 'macos',
    'ios', 'android', 'blackberry', 'symbian', 'windows phone', 'firefoxos', 'tizen', 'sailfish',
    'kaios', 'ubuntu touch', 'firefox mobile', 'chrome mobile', 'safari mobile', 'opera mobile',
    'edge mobile', 'samsunginternet', 'uc browser', 'qq browser', 'baidu browser', 'yandex browser',
    'opera mini', 'ucweb', 'bolt', 'teashark', 'skyfire', 'blazer', 'icecat', 'iceape', 'seamonkey',
    'waterfox', 'pale moon', 'basilisk', 'k-meleon', 'galeon', 'epiphany', 'dillo', 'links2', 'elinks',
    'w3m', 'lynx', 'edbrowse', 'netpositive', 'voyager', 'aweb', 'ibrowse', 'amaya', 'wmosaic',
    'mosaic', 'cern linemode', 'lynx', 'www-mirror', 'netscape', 'mosaic', 'worldwideweb', 'libwww',
    'wwwlib', 'getright', 'goto', 'getweb', 'go-ahead-got', 'go!zilla', 'gotit', 'grabber', 'grabnet',
    'grafula', 'greed', 'gridbot', 'gromit', 'grub-client', 'gulliver', 'harvest', 'havindex', 'hazel',
    'htdig', 'htmlgobble', 'hyperdecontextualizer', 'h�m�h�kki', 'ia_archiver', 'ibm_planetwork',
    'imagemosaic', 'incywincy', 'informant', 'infospider', 'inktomi', 'inspectorwww', 'intelliagent',
    'internetseer', 'iral', 'irobot', 'iron33', 'israelisearch', 'jBot', 'jeeves', 'jobo', 'jpeg',
    'jobo', 'join', 'jubii', 'jumpstation', 'katipo', 'kdd-explorer', 'kilroy', 'ko_yappo_robot',
    'labelgrabber', 'larbin', 'legs', 'libwww-perl', 'link', 'linkidator', 'linkscan', 'linkwalker',
    'lockon', 'logo_gif', 'lwp', 'lycos', 'magpie', 'mantraagent', 'martin', 'marvin', 'mattie',
    'mediafox', 'mediapartners', 'mercator', 'merzscope', 'microsoft url control', 'minotaur',
    'miixpc', 'miva', 'mj12bot', 'mnogosearch', 'moget', 'momspider', 'monster', 'motor', 'muncher',
    'muscatferret', 'mwd.search', 'myweb', 'nazio', 'nec-meshexplorer', 'nederland.zoek', 'netants',
    'netmechanic', 'netscoop', 'newscan-online', 'nhse', 'nomad', 'noyona', 'nutch', 'nzexplorer',
    'occam', 'octopus', 'openfind', 'openintegrity', 'orbsearch', 'packrat', 'pageboy', 'pager',
    'patric', 'pegasus', 'perlcrawler', 'perman', 'petersnews', 'phantom', 'phpdig', 'picosearch',
    'piltdownman', 'pimptrain', 'pinpoint', 'pioneer', 'plucker', 'pogodak', 'pompos', 'poppi',
    'poppy', 'portalb', 'psbot', 'python', 'rambler', 'raven', 'rbse', 'resume', 'roadhouse', 'robbie',
    'robofox', 'robozilla', 'roverbot', 'rules', 'safetynet', 'salmagundi', 'scooter', 'scoutjet',
    'scrubby', 'search', 'searchprocess', 'semanticdiscovery', 'senrigan', 'sg-scout', 'shagseeker',
    'shai', 'simmany', 'sitemapper', 'sitevalet', 'sitetech', 'slcrawler', 'sleek', 'smartwit', 'snooper',
    'solbot', 'spider', 'spiderlytics', 'spidermonkey', 'spiderview', 'spry', 'sqworm', 'ssearcher',
    'suke', 'suntek', 'surfer', 'sven', 'sygol', 'tach', 'tarantula', 'tarspider', 'tcl_http',
    'techbot', 'templeton', 'teoma', 'teradex', 'titin', 'titan', 'tkens', 'tlspider', 'toutatis',
    't-h-u-n-d-e-r-s-t-o-n-e', 'turnitinbot', 'turtle', 'tv33', 'twiceler', 'twisted PageGetter',
    'ucmore', 'udmsearch', 'urlck', 'urlresolver', 'valkyrie', 'victoria', 'vision-search', 'voidbot',
    'voyager', 'vwbot_k', 'w3index', 'w3m2', 'wallpaper', 'wanderer', 'wapspider', 'watchdog',
    'wavefire', 'webbandit', 'webcatcher', 'webclipping', 'webcollage', 'webcopy', 'webcraft',
    'webdevil', 'webdownloader', 'webdup', 'webfetch', 'webfoot', 'webinator', 'weblayers',
    'weblinker', 'weblog', 'webmirror', 'webmonkey', 'webquest', 'webreaper', 'websquash',
    'webspider', 'webster', 'webstripper', 'webvac', 'webwalk', 'webwalker', 'webwatch',
    'webwombat', 'webzip', 'wget', 'whizbang', 'whowhere', 'wildferret', 'worldlight', 'wwwc',
    'wwwster', 'xget', 'xyleme', 'yacy', 'yandex', 'yanga', 'yeti', 'yodao', 'yooglifetchagent',
    'zeal', 'zeus', 'zippy', 'zoom', 'zspider'
  ];

  for (const pattern of maliciousPatterns) {
    if (ua.includes(pattern)) {
      return { isMalicious: true, reason: 'Blacklisted Tool Detected', tool: pattern };
    }
  }

  return { isMalicious: false, reason: 'Clean', tool: null };
}

export default async function handler(req, res) {
  const userAgent = req.headers['user-agent'] || '';
  // Handle potential multiple IPs in x-forwarded-for, take the first one (client IP)
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  // --- SECURITY BYPASS: WHITELIST CHECK ---
  // If IP is in the whitelist, bypass all security checks.
  if (WHITELISTED_IPS.includes(ip)) {
    console.log(`[ACCESS ALLOWED] Whitelisted IP detected: ${ip}`);
    
    // Proceed to normal endpoint logic (Roblox vs Browser)
    // BUT we don't need to check blacklist anymore.
  } else {
    // If NOT in whitelist, perform strict security checks.

    // 1. IF ACCESSED BY ROBLOX -> SERVE WW-6 PROTECTION
    // Note: Roblox requests are usually safe from blacklist tools, but still filtered.
    if (userAgent.includes('Roblox/WinInet') || userAgent.includes('Roblox/Lua')) {
      try {
        // MAIN and ONLY protection script loaded in-game
        const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-6');
        const scriptContent = await response.text();
        
        res.setHeader('Content-Type', 'text/plain');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        return res.status(200).send(scriptContent);
      } catch (err) {
        return res.status(500).send('-- Error loading protection script.');
      }
    }

    // 2. CHECK BLACKLIST (STRICT) - Only if IP is not whitelisted
    const check = isMaliciousTool(userAgent);

    if (check.isMalicious) {
      // Database Logging (Optional)
      try {
        await client.connect();
        const db = client.db('pinat_protection');
        await db.collection('blacklisted_ips').updateOne(
          { ip: ip }, 
          { $set: { reason: check.reason, tool: check.tool, date: new Date() } }, 
          { upsert: true }
        );
      } catch (e) { console.error(e); } finally { await client.close(); }

      // Send Discord Log
      await sendDiscordLog(ip, check.reason, userAgent, check.tool);

      // Render Blacklist Page
      res.setHeader('Content-Type', 'text/html');
      return res.status(403).send(renderBlacklist(ip, check.reason, check.tool));
    }
  }

  // 3. IF NORMAL BROWSER (OR WHITELISTED USER) -> SHOW PREMIUM UI (VERCEL STYLE) WITH DETAILED GAME INFO
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PinatHub • Premium Scripts</title>
        
        <!-- Fonts -->
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&family=Orbitron:wght@500;700;900&display=swap" rel="stylesheet">
        
        <!-- Tailwind CSS -->
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            background: "#030304",
                            surface: "#0e0e10",
                            surfaceHighlight: "#18181b",
                            primary: "#ffffff",
                            secondary: "#a1a1aa",
                            accent: "#6366f1", // Indigo
                            accentGlow: "#818cf8",
                            danger: "#ef4444"
                        },
                        fontFamily: {
                            sans: ['Inter', 'sans-serif'],
                            mono: ['JetBrains Mono', 'monospace'],
                            display: ['Orbitron', 'sans-serif'],
                        },
                        backgroundImage: {
                            'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
                            'hero-glow': 'conic-gradient(from 180deg at 50% 50%, #2a2a2a 0deg, #030304 180deg, #000000 360deg)',
                            'grid-pattern': "linear-gradient(to right, #1f1f22 1px, transparent 1px), linear-gradient(to bottom, #1f1f22 1px, transparent 1px)"
                        },
                        animation: {
                            'fade-in': 'fadeIn 0.8s ease-out forwards',
                            'slide-up': 'slideUp 0.8s cubic-bezier(0.16, 1, 0.3, 1) forwards',
                            'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
                            'float': 'float 6s ease-in-out infinite',
                            'glow': 'glow 2s ease-in-out infinite alternate',
                        },
                        keyframes: {
                            fadeIn: {
                                '0%': { opacity: '0' },
                                '100%': { opacity: '1' },
                            },
                            slideUp: {
                                '0%': { opacity: '0', transform: 'translateY(20px)' },
                                '100%': { opacity: '1', transform: 'translateY(0)' },
                            },
                            float: {
                                '0%, 100%': { transform: 'translateY(0)' },
                                '50%': { transform: 'translateY(-10px)' },
                            },
                            glow: {
                                'from': { boxShadow: '0 0 10px -5px #6366f1' },
                                'to': { boxShadow: '0 0 25px 5px #6366f1' },
                            }
                        }
                    }
                }
            }
        </script>
        
        <style>
            /* Base Settings */
            :root {
                --cursor-size: 20px;
            }
            body { 
                background-color: #030304; 
                color: #fff;
                overflow-x: hidden;
                -webkit-font-smoothing: antialiased;
            }

            /* Glassmorphism */
            .glass-panel {
                background: rgba(14, 14, 16, 0.6);
                backdrop-filter: blur(12px);
                -webkit-backdrop-filter: blur(12px);
                border: 1px solid rgba(255, 255, 255, 0.08);
                box-shadow: 0 4px 30px rgba(0, 0, 0, 0.3);
            }

            /* Grid Background */
            .bg-grid {
                background-size: 50px 50px;
                mask-image: linear-gradient(to bottom, black 40%, transparent 100%);
                -webkit-mask-image: linear-gradient(to bottom, black 40%, transparent 100%);
            }

            /* Custom Scrollbar */
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #030304; }
            ::-webkit-scrollbar-thumb { background: #27272a; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: #3f3f46; }

            /* Code Block Terminal Style */
            .code-block {
                background: #09090b;
                border: 1px solid #27272a;
                position: relative;
                overflow: hidden;
            }
            .code-block::before {
                content: '';
                position: absolute;
                top: 0; left: 0; right: 0; height: 1px;
                background: linear-gradient(90deg, transparent, #6366f1, transparent);
            }
            .code-text { color: #a5b4fc; text-shadow: 0 0 10px rgba(165, 180, 252, 0.3); }

            /* Utilities */
            .text-glow { text-shadow: 0 0 20px rgba(99, 102, 241, 0.5); }
            .border-glow:hover { box-shadow: 0 0 15px rgba(99, 102, 241, 0.2); border-color: rgba(99, 102, 241, 0.4); }
            
            /* Loader Animation */
            .loader-bar {
                background: linear-gradient(90deg, #6366f1, #818cf8, #6366f1);
                background-size: 200% 100%;
                animation: loading 2s infinite linear;
            }
            @keyframes loading { 0% { background-position: 100% 0; } 100% { background-position: -100% 0; } }

            /* Toast Notification */
            #toast-container {
                position: fixed;
                bottom: 24px;
                right: 24px;
                z-index: 50;
                pointer-events: none;
            }
            .toast {
                background: rgba(14, 14, 16, 0.95);
                border: 1px solid #27272a;
                border-left: 4px solid #6366f1;
                color: white;
                padding: 16px 24px;
                margin-top: 12px;
                border-radius: 8px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.5);
                display: flex;
                align-items: center;
                gap: 12px;
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.4s cubic-bezier(0.16, 1, 0.3, 1);
            }
            .toast.show { opacity: 1; transform: translateY(0); }
        </style>
    </head>
    <body class="min-h-screen flex flex-col items-center relative selection:bg-accent selection:text-white">
        
        <!-- Ambient Background Effects -->
        <div class="fixed inset-0 pointer-events-none -z-10">
            <!-- Grid -->
            <div class="absolute inset-0 bg-grid opacity-20"></div>
            <!-- Radial Glows -->
            <div class="absolute top-[-10%] left-[-10%] w-[500px] h-[500px] bg-accent/20 rounded-full blur-[120px] opacity-40 animate-pulse-slow"></div>
            <div class="absolute bottom-[10%] right-[-10%] w-[600px] h-[600px] bg-purple-900/10 rounded-full blur-[120px] opacity-30"></div>
        </div>

        <!-- Main Container -->
        <div class="w-full max-w-7xl px-4 md:px-8 py-12 md:py-20 relative z-10">
            
            <!-- Header / Logo Section -->
            <div class="flex flex-col items-center text-center mb-16 md:mb-24 animate-slide-up" style="animation-delay: 0.1s;">
                <div class="relative group mb-6">
                    <!-- Glow Effect Behind Logo -->
                    <div class="absolute inset-0 bg-accent/20 blur-2xl rounded-full opacity-0 group-hover:opacity-100 transition-opacity duration-700"></div>
                    
                    <img src="https://files.catbox.moe/s6agav.png" alt="PinatHub Logo" 
                         class="w-28 h-28 md:w-36 md:h-36 rounded-full relative z-10 border border-white/10 shadow-2xl shadow-black/50 animate-float">
                </div>
                
                <h1 class="text-5xl md:text-7xl font-display font-black tracking-tighter mb-4 text-white relative">
                    <span class="text-transparent bg-clip-text bg-gradient-to-r from-white via-gray-200 to-gray-500">Pinat</span>
                    <span class="text-transparent bg-clip-text bg-gradient-to-r from-accent to-purple-400 text-glow">Hub</span>
                    <!-- Decorative underline -->
                    <div class="h-1 w-24 bg-gradient-to-r from-accent to-transparent mx-auto mt-4 rounded-full"></div>
                </h1>
                
                <p class="text-secondary text-lg md:text-xl font-light tracking-wide max-w-2xl leading-relaxed">
                    Advanced Roblox Execution Environment <br class="hidden md:block" />
                    <span class="text-accent/80 font-mono text-sm mt-2 block">v4.0.2 // SECURE CONNECTION</span>
                </p>
            </div>

            <!-- Content Layout -->
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
                
                <!-- Left Column: Universal Loader (Span 5) -->
                <div class="lg:col-span-5 animate-slide-up sticky top-8" style="animation-delay: 0.2s;">
                    <div class="glass-panel rounded-2xl p-6 md:p-8 border border-white/5 hover:border-accent/30 transition-all duration-300 group">
                        <div class="flex items-center justify-between mb-6">
                            <h2 class="text-xl font-display font-bold text-white flex items-center gap-3">
                                <div class="p-2 bg-accent/10 rounded-lg text-accent">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                                </div>
                                Universal Loader
                            </h2>
                            <div class="flex items-center gap-2 px-3 py-1 rounded-full bg-green-500/10 border border-green-500/20">
                                <span class="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
                                <span class="text-[10px] font-mono font-bold uppercase text-green-400">Online</span>
                            </div>
                        </div>
                        
                        <p class="text-secondary text-sm leading-relaxed mb-6 border-l-2 border-white/10 pl-4">
                            Execute this payload in your executor. The neural engine will automatically identify the game context and load the appropriate module.
                        </p>
                        
                        <!-- Enhanced Code Block -->
                        <div class="code-block rounded-xl overflow-hidden mb-6 group-hover:shadow-[0_0_20px_-5px_rgba(99,102,241,0.15)] transition-shadow">
                            <div class="flex items-center justify-between px-4 py-2 bg-[#0f0f11] border-b border-white/5">
                                <div class="flex gap-2">
                                    <div class="w-3 h-3 rounded-full bg-red-500/80"></div>
                                    <div class="w-3 h-3 rounded-full bg-yellow-500/80"></div>
                                    <div class="w-3 h-3 rounded-full bg-green-500/80"></div>
                                </div>
                                <div class="text-[10px] font-mono text-zinc-500 uppercase">Lua Script</div>
                            </div>
                            <div class="p-4 overflow-x-auto">
                                <code id="loader-code" class="font-mono text-xs md:text-sm code-text block break-all">loadstring(game:HttpGet("https://raw.githubusercontent.com/xploitforceofficial-stack/pinatpublicloader/refs/heads/main/pinatloader.lua"))()</code>
                            </div>
                            <!-- Decorative scan line -->
                            <div class="absolute inset-0 pointer-events-none bg-gradient-to-b from-transparent via-white/5 to-transparent h-[10px] w-full animate-[loading_3s_linear_infinite] opacity-20 top-0"></div>
                        </div>
                    
                        <button onclick="copyLoader()" class="w-full py-4 bg-white text-black font-display font-bold text-sm rounded-xl hover:bg-gray-100 transition-all transform hover:scale-[1.02] active:scale-[0.98] flex items-center justify-center gap-3 shadow-[0_0_20px_-5px_rgba(255,255,255,0.3)] relative overflow-hidden group/btn">
                            <div class="absolute inset-0 bg-gradient-to-r from-transparent via-white/50 to-transparent translate-x-[-100%] group-hover/btn:translate-x-[100%] transition-transform duration-700"></div>
                            <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                            <span id="copy-text">Initialize Copy</span>
                        </button>
                    </div>
                </div>

                <!-- Right Column: Supported Games & Details (Span 7) -->
                <div class="lg:col-span-7 space-y-6 animate-slide-up" style="animation-delay: 0.3s;">
                    
                    <!-- Description Panel -->
                    <div class="glass-panel p-6 md:p-8 rounded-2xl border-l-4 border-l-accent relative overflow-hidden">
                        <div class="absolute top-0 right-0 p-4 opacity-10">
                            <svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 24 24" fill="currentColor"><path d="M12 2L2 7l10 5 10-5-10-5zm0 9l2.5-1.25L12 8.5l-2.5 1.25L12 11zm0 2.5l-5-2.5-5 2.5L12 22l10-8.5-5-2.5-5 2.5z"/></svg>
                        </div>
                        <h2 class="text-2xl font-display font-bold text-white mb-4">System Architecture</h2>
                        <p class="text-secondary text-sm leading-relaxed max-w-lg">
                            PinatHub utilizes a heuristic engine to deliver <span class="text-white font-semibold border-b border-accent/50">Auto-Farming</span>, <span class="text-white font-semibold border-b border-accent/50">PVP Dominance</span>, and <span class="text-white font-semibold border-b border-accent/50">ESP Visualization</span>. Protected by enterprise-grade obfuscation to ensure integrity against anti-tamper mechanisms.
                        </p>
                    </div>

                    <!-- Games List Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        
                        <!-- Game 1 -->
                        <div class="glass-panel p-5 rounded-xl border border-white/5 hover:border-blue-500/50 transition-all duration-300 hover:-translate-y-1 group">
                            <div class="flex items-center gap-3 mb-3">
                                <div class="w-10 h-10 rounded bg-blue-500/10 flex items-center justify-center text-blue-400 font-bold font-display text-sm group-hover:scale-110 transition-transform duration-300">TSB</div>
                                <h3 class="font-bold text-white tracking-wide">The Strongest Battlegrounds</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Dominate combat loops with <span class="text-blue-300">Auto Click</span>, Infinite Yield, and precision Targeting Logic.
                            </p>
                        </div>

                        <!-- Game 2 -->
                        <div class="glass-panel p-5 rounded-xl border border-white/5 hover:border-purple-500/50 transition-all duration-300 hover:-translate-y-1 group">
                            <div class="flex items-center gap-3 mb-3">
                                <div class="w-10 h-10 rounded bg-purple-500/10 flex items-center justify-center text-purple-400 font-bold font-display text-sm group-hover:scale-110 transition-transform duration-300">BB</div>
                                <h3 class="font-bold text-white tracking-wide">Blade Ball</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Perfect timing engine with <span class="text-purple-300">Auto Parry</span>, Spam Module, and Kill Aura protocols.
                            </p>
                        </div>

                        <!-- Game 3 -->
                        <div class="glass-panel p-5 rounded-xl border border-white/5 hover:border-red-500/50 transition-all duration-300 hover:-translate-y-1 group">
                            <div class="flex items-center gap-3 mb-3">
                                <div class="w-10 h-10 rounded bg-red-500/10 flex items-center justify-center text-red-400 font-bold font-display text-sm group-hover:scale-110 transition-transform duration-300">STA</div>
                                <h3 class="font-bold text-white tracking-wide">Survive The Apocalypse</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Loot optimization with <span class="text-red-300">Auto Gathering</span>, Item ESP, and Weapon Modification suite.
                            </p>
                        </div>

                        <!-- Game 4 -->
                        <div class="glass-panel p-5 rounded-xl border border-white/5 hover:border-yellow-500/50 transition-all duration-300 hover:-translate-y-1 group">
                            <div class="flex items-center gap-3 mb-3">
                                <div class="w-10 h-10 rounded bg-yellow-500/10 flex items-center justify-center text-yellow-400 font-bold font-display text-sm group-hover:scale-110 transition-transform duration-300">HF</div>
                                <h3 class="font-bold text-white tracking-wide">Heavyweight Fishing</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Automated angling with <span class="text-yellow-300">Instant Reel</span>, Auto Cast, and Duplication Market tactics.
                            </p>
                        </div>

                    </div>
                </div>
            </div>

            <!-- Footer -->
            <div class="mt-20 pt-8 border-t border-white/5 flex flex-col md:flex-row justify-between items-center gap-4 text-zinc-600 text-xs font-mono animate-fade-in" style="animation-delay: 0.5s;">
                <p>SECURE ESTABLISHMENT // PINATHUB GUARD</p>
                <p class="flex items-center gap-2">
                    <span class="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                    SYSTEM OPERATIONAL
                </p>
            </div>
        </div>

        <!-- Toast Notification Container -->
        <div id="toast-container"></div>

        <script>
            function showToast(message, type = 'success') {
                const container = document.getElementById('toast-container');
                const toast = document.createElement('div');
                toast.className = 'toast';
                
                // Icon
                let icon = type === 'success' 
                    ? '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>'
                    : '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#f87171" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>';

                toast.innerHTML = \`\${icon}<span class="font-medium text-sm">\${message}</span>\`;
                container.appendChild(toast);

                // Animate In
                requestAnimationFrame(() => {
                    toast.classList.add('show');
                });

                // Remove after 3s
                setTimeout(() => {
                    toast.classList.remove('show');
                    setTimeout(() => toast.remove(), 400);
                }, 3000);
            }

            function copyLoader() {
                const code = document.getElementById('loader-code').innerText;
                const btnText = document.getElementById('copy-text');
                const originalText = btnText.innerText;

                navigator.clipboard.writeText(code).then(() => {
                    // Button Feedback
                    btnText.innerText = 'Copied to Clipboard';
                    showToast('Script payload copied successfully');

                    setTimeout(() => {
                        btnText.innerText = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                    showToast('Failed to copy script', 'error');
                });
            }
        </script>
    </body>
    </html>
  `);
}
