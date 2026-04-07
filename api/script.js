export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const secFetchSite = req.headers['sec-fetch-site'] || '';
  const xForwardedFor = req.headers['x-forwarded-for'] || 'unknown';

  // 1. daftar blacklist super ketat (terminal, editor, library, tools)
  const forbiddenTools = [
    'curl', 'wget', 'powershell', 'powershell-core', 'pwsh', 'vscode', 
    'insomnia', 'postman', 'python', 'python-requests', 'node-fetch', 
    'termux', 'terminal', 'axios', 'go-http-client', 'bruno', 'httpie',
    'rest-client', 'libcurl', 'wininet' // wininet sering dipake tools windows luar roblox
  ];

  // 2. deteksi lingkungan roblox asli
  // roblox game client asli selalu menyertakan "Roblox" dan bukan "RobloxStudio"
  const isRoblox = userAgent.includes('roblox') && !userAgent.includes('robloxstudio');
  const isForbidden = forbiddenTools.some(tool => userAgent.includes(tool));

  // 3. logika pertahanan: jika terdeteksi tool terminal atau buka di browser
  if (isForbidden || !isRoblox || secFetchSite === 'same-origin') {
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
              .logo { margin-bottom: 20px; }
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
                  <p id="q-sub">kami mendeteksi kaka pake ${isForbidden ? 'terminal/tools' : 'browser'}. silakan verifikasi kalo kaka bukan skidder.</p>
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
              function next() {
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
                      document.getElementById('q-stage').classList.add('hidden');
                      document.getElementById('log-stage').classList.remove('hidden');
                      const term = document.getElementById('term');
                      term.style.display = 'block';
                      const logs = [
                          "> target_ip: ${xForwardedFor}",
                          "> user_agent: detected_illegal",
                          "> status: skidder_confirmed",
                          "> payload: unauthorized_fetch",
                          "> sending_webhook: success",
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
  }

  // 4. bagian akses aman (hanya tembus lewat Roblox Game Client)
  try {
    const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
    const content = await response.text();

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate'); // anti cache
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // tambahkan sedikit delay palsu agar terlihat seperti verifikasi asli di dalam game
    return res.status(200).send(content);
  } catch (err) {
    return res.status(500).send('-- [pinathub-error]: database offline.');
  }
}
