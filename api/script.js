export default async function handler(req, res) {
  const userAgent = req.headers['user-agent'] || '';
  const secFetchSite = req.headers['sec-fetch-site'] || '';
  
  // 1. Daftar Blacklist Tools & Terminal
  const forbiddenTools = [
    'curl', 'wget', 'powershell', 'vscode', 'insomnia', 
    'postman', 'python', 'node-fetch', 'termux', 'terminal', 'axios'
  ];

  const isForbidden = forbiddenTools.some(tool => userAgent.toLowerCase().includes(tool));
  
  // 2. Deteksi Lingkungan Roblox
  // game:HttpGet mengirimkan User-Agent yang mengandung "Roblox"
  const isRoblox = userAgent.includes('Roblox');

  // Jika terdeteksi akses dari Browser, Terminal, atau VS Code
  if (isForbidden || !isRoblox || secFetchSite === 'same-origin') {
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <!DOCTYPE html>
      <html>
      <head>
          <title>Access Denied</title>
          <style>
              body { background: #0a0a0a; color: #00ffcc; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; font-family: 'Courier New', monospace; }
              .box { border: 1px solid #00ffcc; padding: 30px; border-radius: 8px; text-align: center; box-shadow: 0 0 15px rgba(0, 255, 204, 0.3); }
              h1 { font-size: 20px; }
          </style>
      </head>
      <body>
          <div class="box">
              <h1>eits mau ngapain kaka?</h1>
              <p>disini tidak ada apa apa kok</p>
          </div>
      </body>
      </html>
    `);
  }

  try {
    // 3. Mengambil script asli dari GitLua secara internal (Server-side)
    const response = await fetch('https://gitlua.tuffgv.my.id/raw/www-1');
    const scriptData = await response.text();

    // 4. Kirim sebagai Plain Text agar bisa dibaca loadstring
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Cache-Control', 'no-store'); // Mencegah caching agar update script real-time
    return res.status(200).send(scriptData);
    
  } catch (error) {
    return res.status(500).send('-- Error: Gagal mengambil source script.');
  }
}
