export default async function handler(req, res) {
  const userAgent = req.headers['user-agent'] || '';
  
  // Deteksi Lingkungan
  const isRoblox = userAgent.includes('Roblox');
  
  // Jika diakses dari Browser/Terminal
  if (!isRoblox) {
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Ujian Masuk PinatHub</title>
          <style>
              body { background: #000; color: #0f0; font-family: 'Courier New', monospace; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
              .quiz-container { border: 2px solid #0f0; padding: 30px; width: 450px; text-align: left; box-shadow: 0 0 20px #0f0; }
              h1 { font-size: 18px; color: #ff0055; text-align: center; border-bottom: 1px solid #0f0; padding-bottom: 10px; }
              .question { margin: 20px 0 15px; font-weight: bold; }
              .option { display: block; background: #111; border: 1px solid #333; color: #0f0; padding: 10px; margin: 5px 0; cursor: pointer; text-decoration: none; transition: 0.3s; }
              .option:hover { background: #0f0; color: #000; }
              .status { font-size: 12px; color: #555; margin-top: 20px; text-align: center; }
              #result { display: none; text-align: center; color: #ff0; }
          </style>
      </head>
      <body>
          <div class="quiz-container" id="quiz">
              <h1>⚠️ SKIDDER DETECTION TEST ⚠️</h1>
              <p style="font-size: 12px;">Untuk melihat script, jawab pertanyaan teknis di bawah ini:</p>
              
              <div class="question" id="qText">Apa fungsi utama dari Ctrl+C dan Ctrl+V bagi seorang "Developer" seperti kamu?</div>
              
              <div id="options">
                  <div class="option" onclick="wrong('Salah! Itu mah jawaban orang pinter.')">A. Mengcopy dokumentasi resmi</div>
                  <div class="option" onclick="correct()">B. Nafas dan jalan hidup saya (Curi Script)</div>
                  <div class="option" onclick="wrong('Ngelawak kamu? Mana ada skidder baca manual.')">C. Memindahkan data backup</div>
              </div>

              <div class="status">Security Level: High | Mode: Anti-Skid</div>
          </div>

          <div class="quiz-container" id="result">
              <h1 id="resTitle">FIX SKIDDER!</h1>
              <p id="resMsg"></p>
              <button onclick="location.reload()" style="background:#0f0; border:none; padding:10px; cursor:pointer;">Ulangi Ujian</button>
          </div>

          <script>
              function correct() {
                  document.getElementById('quiz').style.display = 'none';
                  document.getElementById('result').style.display = 'block';
                  document.getElementById('resTitle').innerHTML = "WADUH JUJUR BANGET!";
                  document.getElementById('resMsg').innerHTML = "Karena kamu ngaku kalau kamu cuma modal copas, scriptnya tetap gak bakal saya kasih. <br><br><b>Sadar diri itu penting, kak. 😊</b>";
              }

              function wrong(msg) {
                  document.getElementById('quiz').style.display = 'none';
                  document.getElementById('result').style.display = 'block';
                  document.getElementById('resTitle').innerHTML = "DETEKSI GAGAL!";
                  document.getElementById('resMsg').innerHTML = msg + "<br><br>Udah skidder, sok pinter lagi. Tobat kak!";
              }
          </script>
      </body>
      </html>
    `);
  }

  // Jika diakses dari Game (Roblox) - Tetap ambil script asli
  try {
    const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
    const scriptData = await response.text();

    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'no-store');
    return res.status(200).send(scriptData);
    
  } catch (error) {
    return res.status(500).send('-- [PinatHub]: Server lagi ngopi, coba lagi nanti.');
  }
}
