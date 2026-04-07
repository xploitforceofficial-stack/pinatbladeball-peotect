export default async function handler(req, res) {
  const userAgent = req.headers['user-agent'] || '';
  const isRoblox = userAgent.includes('Roblox');

  if (!isRoblox) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html lang="id">
      <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>vercel | deployment protection</title>
          <style>
              :root { --bg: #ffffff; --fg: #000; --accents-1: #fafafa; --accents-2: #eaeaea; --error: #ff0000; }
              * { box-sizing: border-box; }
              body { background: var(--bg); color: var(--fg); font-family: -apple-system, system-ui, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; -webkit-font-smoothing: antialiased; }
              .card { width: 100%; max-width: 500px; padding: 40px; border: 1px solid var(--accents-2); border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.05); transition: all 0.3s ease; }
              .logo { margin-bottom: 20px; }
              h1 { font-size: 22px; font-weight: 600; letter-spacing: -0.05rem; margin: 0 0 10px; }
              p { color: #666; font-size: 14px; line-height: 1.6; margin-bottom: 25px; }
              .step-info { font-size: 12px; color: #999; margin-bottom: 10px; text-transform: lowercase; }
              
              /* quiz styles */
              .option { 
                  display: block; width: 100%; padding: 14px 16px; margin-bottom: 10px; 
                  background: var(--bg); border: 1px solid var(--accents-2); border-radius: 6px; 
                  color: var(--fg); font-size: 13px; cursor: pointer; transition: 0.15s; text-align: left;
              }
              .option:hover { border-color: #000; background: var(--accents-1); }
              
              /* features */
              .hidden { display: none; }
              .progress-bg { width: 100%; height: 4px; background: var(--accents-2); border-radius: 2px; margin-bottom: 20px; overflow: hidden; }
              .progress-fill { width: 0%; height: 100%; background: #000; transition: width 0.5s ease; }
              .terminal { background: #000; color: #00ff00; padding: 15px; border-radius: 6px; font-family: monospace; font-size: 11px; margin-top: 20px; display: none; }
              
              .btn-primary { background: #000; color: #fff; border: none; padding: 12px 24px; border-radius: 6px; cursor: pointer; font-size: 14px; width: 100%; margin-top: 10px; }
              .btn-primary:hover { background: #333; }
              
              .alert { color: var(--error); font-size: 12px; margin-top: 10px; font-weight: 500; }
          </style>
      </head>
      <body>
          <div class="card">
              <svg class="logo" width="26" height="23" viewBox="0 0 76 65" fill="#000"><path d="M37.5274 0L75.0548 65H0L37.5274 0Z"/></svg>
              
              <!-- stage 1: pre-check -->
              <div id="step-1">
                  <div class="step-info">step 01/03 • verification</div>
                  <h1>detecting environment..</h1>
                  <p>kami mendeteksi akses dari luar lingkungan game. demi keamanan asset, silakan konfirmasi identitas kaka.</p>
                  <button class="btn-primary" onclick="nextStep(2)">lanjutkan verifikasi</button>
              </div>

              <!-- stage 2: the exam -->
              <div id="step-2" class="hidden">
                  <div class="step-info">step 02/03 • technical quiz</div>
                  <div class="progress-bg"><div class="progress-fill" id="pb"></div></div>
                  <h1 id="q-title">pertanyaan 1..</h1>
                  <div id="quiz-options"></div>
                  <div id="warning-msg" class="alert hidden">pilih jawaban yang bener mang..</div>
              </div>

              <!-- stage 3: report process -->
              <div id="step-3" class="hidden">
                  <div class="step-info">step 03/03 • reporting</div>
                  <h1>sedang memproses..</h1>
                  <p>jawaban disimpan. sistem sedang mengirim log akses ke database owner untuk review manual.</p>
                  <div class="terminal" id="term"></div>
                  <div id="final-btn" class="hidden">
                      <button class="btn-primary" onclick="location.reload()">selesai</button>
                  </div>
              </div>
          </div>

          <script>
              let currentQ = 0;
              const questions = [
                  { 
                      q: "apa alasan utama lu buka link ini di browser?", 
                      o: ["mau belajar (bohong)", "mau inspect link aslinya", "iseng aja siapa tau hoki", "nyari celah buat di leak"] 
                  },
                  { 
                      q: "darimana lu dapet link ini?", 
                      o: ["nemu di discord orang", "nyolong dari script loader", "dikasih temen yang skid juga", "lagi nyari bahan konten tiktok"] 
                  },
                  { 
                      q: "kalo script ini ke-leak, siapa yang rugi?", 
                      o: ["owner (bodo amat)", "user (kasian)", "gua (kalo di ban)", "ga ada, kan gua cuma skid"] 
                  }
              ];

              function nextStep(s) {
                  document.getElementById('step-1').classList.add('hidden');
                  document.getElementById('step-2').classList.remove('hidden');
                  loadQuestion();
              }

              function loadQuestion() {
                  if (currentQ >= questions.length) {
                      finishQuiz();
                      return;
                  }
                  document.getElementById('pb').style.width = ((currentQ / questions.length) * 100) + "%";
                  document.getElementById('q-title').innerText = questions[currentQ].q;
                  const wrapper = document.getElementById('quiz-options');
                  wrapper.innerHTML = '';
                  questions[currentQ].o.forEach(opt => {
                      const btn = document.createElement('button');
                      btn.className = 'option';
                      btn.innerText = opt;
                      btn.onclick = () => { currentQ++; loadQuestion(); };
                      wrapper.appendChild(btn);
                  });
              }

              function finishQuiz() {
                  document.getElementById('step-2').classList.add('hidden');
                  document.getElementById('step-3').classList.remove('hidden');
                  const term = document.getElementById('term');
                  term.style.display = 'block';
                  
                  const logs = [
                      "> sending data to gitlua master...",
                      "> collecting browser metadata...",
                      "> ip logged: " + (Math.floor(Math.random() * 255) + ".168.1.1"),
                      "> skidder_status: confirmed",
                      "> reporting to admin via webhook...",
                      "> access permanently blacklisted."
                  ];

                  let i = 0;
                  const interval = setInterval(() => {
                      term.innerHTML += logs[i] + "<br>";
                      i++;
                      if (i >= logs.length) {
                          clearInterval(interval);
                          document.getElementById('final-btn').classList.remove('hidden');
                      }
                  }, 800);
              }
          </script>
      </body>
      </html>
    `);
  }

  // eksekusi asli buat roblox
  try {
    const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
    const content = await response.text();
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(content);
  } catch (err) {
    return res.status(500).send('-- [error]: database gitlua offline.');
  }
}
