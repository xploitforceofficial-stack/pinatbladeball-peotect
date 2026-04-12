import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

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
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  // 1. IF ACCESSED BY ROBLOX -> SERVE WW-6 PROTECTION
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

  // 2. CHECK BLACKLIST (STRICT)
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

  // 3. IF NORMAL BROWSER -> SHOW PREMIUM UI (VERCEL STYLE) WITH DETAILED GAME INFO
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`
    <!DOCTYPE html>
    <html lang="en" class="dark">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PinatHub • Premium Scripts</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <script>
            tailwind.config = {
                darkMode: 'class',
                theme: {
                    extend: {
                        colors: {
                            background: "#0a0a0a",
                            surface: "#111111",
                            primary: "#fff",
                            secondary: "#888",
                            accent: "#3291ff", // Vercel Blue
                            danger: "#ff4444"
                        },
                        fontFamily: {
                            sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
                            mono: ['Menlo', 'Monaco', 'Courier New', 'monospace'],
                        }
                    }
                }
            }
        </script>
        <style>
            body { background-color: #000; color: #fff; }
            .glass-panel {
                background: rgba(17, 17, 17, 0.8);
                backdrop-filter: blur(12px);
                border: 1px solid rgba(255, 255, 255, 0.1);
            }
            .code-block {
                background: #000;
                border: 1px solid #333;
            }
            /* Custom Scrollbar */
            ::-webkit-scrollbar { width: 8px; }
            ::-webkit-scrollbar-track { background: #111; }
            ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
            ::-webkit-scrollbar-thumb:hover { background: #555; }
        </style>
    </head>
    <body class="antialiased min-h-screen flex flex-col items-center justify-center p-4 relative overflow-hidden">
        
        <!-- Background Grid Effect -->
        <div class="absolute inset-0 z-0 opacity-20 pointer-events-none" 
             style="background-image: linear-gradient(#333 1px, transparent 1px), linear-gradient(90deg, #333 1px, transparent 1px); background-size: 40px 40px;">
        </div>
        <div class="absolute inset-0 z-0 bg-gradient-to-t from-black via-transparent to-black pointer-events-none"></div>

        <div class="relative z-10 w-full max-w-5xl">
            
            <!-- Header / Logo -->
            <div class="flex flex-col items-center mb-10 text-center">
                <img src="https://files.catbox.moe/s6agav.png" alt="PinatHub Logo" class="w-20 h-20 rounded-full mb-4 shadow-2xl shadow-white/5 border border-white/10">
                <h1 class="text-5xl md:text-6xl font-bold tracking-tighter mb-2 bg-clip-text text-transparent bg-gradient-to-r from-white via-gray-200 to-gray-500">
                    PinatHub
                </h1>
                <p class="text-secondary text-sm md:text-base font-medium tracking-wide">
                    PREMIUM ROBLOX SCRIPTS LIBRARY
                </p>
            </div>

            <!-- Main Content Grid -->
            <div class="grid grid-cols-1 lg:grid-cols-12 gap-6">
                
                <!-- Left Column: Universal Loader (Span 5) -->
                <div class="lg:col-span-5 glass-panel p-6 rounded-xl flex flex-col h-full justify-between group hover:border-accent/50 transition-colors duration-300">
                    <div>
                        <div class="flex items-center justify-between mb-4">
                            <h2 class="text-xl font-bold text-white flex items-center gap-2">
                                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path><polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline><line x1="12" y1="22.08" x2="12" y2="12"></line></svg>
                                Universal Loader
                            </h2>
                            <span class="px-2 py-1 text-[10px] font-bold uppercase bg-green-500/10 text-green-400 border border-green-500/20 rounded-full">Public</span>
                        </div>
                        <p class="text-secondary text-sm leading-relaxed mb-6">
                            Salin kode di bawah ini dan tempelkan ke executor Anda. Loader ini akan otomatis mendeteksi game yang Anda mainkan dan memuat script PinatHub yang sesuai.
                        </p>
                        
                        <!-- Code Block -->
                        <div class="code-block rounded-lg p-4 font-mono text-xs text-green-400 overflow-x-auto relative group">
                            <div class="absolute top-2 right-2 text-zinc-600 text-[10px]">LUA</div>
                            <code id="loader-code">loadstring(game:HttpGet("https://raw.githubusercontent.com/xploitforceofficial-stack/pinatpublicloader/refs/heads/main/pinatloader.lua"))()</code>
                        </div>
                    </div>
                    
                    <button onclick="copyLoader()" class="mt-6 w-full py-3 bg-white text-black font-bold text-sm rounded-lg hover:bg-gray-200 transition-all flex items-center justify-center gap-2 group-active:scale-95">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
                        <span id="copy-text">Copy Universal Loader</span>
                    </button>
                    <p id="copy-feedback" class="text-center text-xs text-green-400 mt-2 opacity-0 transition-opacity">Berhasil disalin ke clipboard!</p>
                </div>

                <!-- Right Column: Supported Games & Details (Span 7) -->
                <div class="lg:col-span-7 flex flex-col gap-6">
                    
                    <!-- Description Panel -->
                    <div class="glass-panel p-6 rounded-xl">
                        <h2 class="text-lg font-semibold text-white mb-3">Tentang PinatHub</h2>
                        <p class="text-secondary text-sm leading-relaxed">
                            PinatHub adalah eksploit Roblox tingkat lanjut yang menyediakan fitur <span class="text-white font-medium">Auto Farm, PvP Advantages, dan ESP</span>. Script kami dilindungi oleh sistem anti-ban (WW-6) dan diperbarui secara berkala untuk memastikan kompatibilitas dengan patch terbaru Roblox.
                        </p>
                    </div>

                    <!-- Games List Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        
                        <!-- Game 1 -->
                        <div class="glass-panel p-4 rounded-lg border-l-4 border-l-blue-500 hover:bg-white/5 transition">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-8 h-8 rounded bg-blue-500/20 flex items-center justify-center text-blue-400 font-bold text-xs">TSB</div>
                                <h3 class="font-bold text-white">The Strongest Battlegrounds</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Dominasi pertempuran dengan fitur <strong>Auto Click, Infinite Yield, dan Target Aimbot</strong>. Script ini dioptimalkan untuk grind skill cepat dan menang dalam setiap duel 1v1.
                            </p>
                        </div>

                        <!-- Game 2 -->
                        <div class="glass-panel p-4 rounded-lg border-l-4 border-l-purple-500 hover:bg-white/5 transition">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-8 h-8 rounded bg-purple-500/20 flex items-center justify-center text-purple-400 font-bold text-xs">BB</div>
                                <h3 class="font-bold text-white">Blade Ball</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Tidak pernah ketinggalan bola lagi. Fitur unggulan termasuk <strong>Auto Parry (Perfect Block), Auto Spam, dan Kill Aura</strong> untuk mengeliminasi lawan secara instan.
                            </p>
                        </div>

                        <!-- Game 3 -->
                        <div class="glass-panel p-4 rounded-lg border-l-4 border-l-red-500 hover:bg-white/5 transition">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-8 h-8 rounded bg-red-500/20 flex items-center justify-center text-red-400 font-bold text-xs">STA</div>
                                <h3 class="font-bold text-white">Survive The Apocalypse</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Bertahan hidup lebih mudah dengan <strong>Auto Loot, ESP Items, dan Weapon Mods</strong>. Temukan persediaan langka sebelum pemain lain dan kuasai peta.
                            </p>
                        </div>

                        <!-- Game 4 -->
                        <div class="glass-panel p-4 rounded-lg border-l-4 border-l-yellow-500 hover:bg-white/5 transition">
                            <div class="flex items-center gap-3 mb-2">
                                <div class="w-8 h-8 rounded bg-yellow-500/20 flex items-center justify-center text-yellow-400 font-bold text-xs">HF</div>
                                <h3 class="font-bold text-white">Heavyweight Fishing</h3>
                            </div>
                            <p class="text-xs text-zinc-400 leading-relaxed">
                                Tingkatkan level memancing Anda dengan <strong>Auto Cast, Auto Reel (Instant), dan Sell Dupe</strong>. Dapatkan ikan langka dan raksasa tanpa usaha.
                            </p>
                        </div>

                    </div>
                </div>
            </div>

            <div class="mt-12 text-center border-t border-white/5 pt-6">
                <p class="text-zinc-600 text-xs font-mono">
                    Protected by PinatHub Guard v4.0 • Endpoint secured by WW-6
                </p>
            </div>
        </div>

        <script>
            function copyLoader() {
                const code = document.getElementById('loader-code').innerText;
                navigator.clipboard.writeText(code).then(() => {
                    const btnText = document.getElementById('copy-text');
                    const feedback = document.getElementById('copy-feedback');
                    
                    btnText.innerText = 'Copied!';
                    feedback.style.opacity = '1';
                    
                    setTimeout(() => {
                        btnText.innerText = 'Copy Universal Loader';
                        feedback.style.opacity = '0';
                    }, 2500);
                }).catch(err => {
                    console.error('Failed to copy: ', err);
                });
            }
        </script>
    </body>
    </html>
  `);
}
