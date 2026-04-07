import { MongoClient } from 'mongodb';

const client = new MongoClient(process.env.MONGODB_URI);

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
      country: data?.location?.country || 'Unknown'
    };
  } catch (err) {
    return { is_vpn: false, is_proxy: false, is_datacenter: false, country: 'Unknown' };
  }
}

// Enhanced Discord logging
async function sendDiscordLog(ip, reason, ua, country = 'Unknown') {
  const webhookUrl = process.env.DISCORD_WEBHOOK_URL;
  if (!webhookUrl) return;

  const data = {
    username: "Pinat Guard Global",
    embeds: [{
      title: "🚨 Security Alert (Global)",
      color: 15158332,
      fields: [
        { name: "🌐 IP Address", value: `\`${ip}\``, inline: true },
        { name: "🌍 Country", value: `\`${country}\``, inline: true },
        { name: "🛡️ Reason", value: `\`${reason}\`` },
        { name: "📱 User Agent", value: `\`${ua}\`` }
      ],
      footer: { text: "PinatHub Protection - No Region Lock" }
    }]
  };
  await fetch(webhookUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data) });
}

export default async function handler(req, res) {
  const userAgent = (req.headers['user-agent'] || '').toLowerCase();
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;

  try {
    await client.connect();
    const db = client.db('pinat_protection');
    const blacklist = db.collection('blacklisted_ips');

    // 1. CEK BLACKLIST (IP BAN)
    const isBlacklisted = await blacklist.findOne({ ip: ip });
    if (isBlacklisted) {
      return res.status(403).send('2d2d20596f757220495020697320426c61636b6c6973746564');
    }

    // 2. DETEKSI ROBLOX (Langsung kasih script asal bukan VPN)
    const isRoblox = userAgent.includes('roblox');

    if (isRoblox) {
      const vpn = await checkVpnProxy(ip);
      if (vpn.is_vpn || vpn.is_proxy || vpn.is_datacenter) {
        await blacklist.insertOne({ ip: ip, reason: 'vpn_detected_roblox', date: new Date() });
        await sendDiscordLog(ip, "VPN/Datacenter Detected (Roblox)", userAgent, vpn.country);
        return res.status(403).send('2d2d2056504e204465746563746564');
      }

      // Ambil script raw
      try {
        const response = await fetch('https://gitlua.tuffgv.my.id/raw/ww-5');
        const content = await response.text();
        const hexEncoded = Buffer.from(content).toString('hex');
        
        res.setHeader('Content-Type', 'text/plain');
        return res.status(200).send(hexEncoded);
      } catch (err) {
        return res.status(500).send('Source Offline');
      }
    }

    // 3. LOGIKA BROWSER (Kuis Blacklist)
    if (req.method === 'POST') {
      await blacklist.insertOne({ ip: ip, reason: 'browser_skid_attempt', date: new Date() });
      await sendDiscordLog(ip, "Manual Browser Access (Blacklisted)", userAgent);
      return res.json({ status: 'banned' });
    }

    // Simple HTML for Browser users
    res.setHeader('Content-Type', 'text/html');
    return res.status(200).send(`
      <body style="background:#000;color:red;display:flex;justify-content:center;align-items:center;height:100vh;font-family:monospace;text-align:center;">
        <div>
          <h1>SECURITY CHECK</h1>
          <p>Browser access is restricted.</p>
          <button onclick="fetch('',{method:'POST'}).then(()=>location.reload())" style="padding:10px;cursor:pointer;">Click to Verify (Bait)</button>
        </div>
      </body>
    `);

  } catch (err) {
    return res.status(500).send('Server Error');
  }
}
