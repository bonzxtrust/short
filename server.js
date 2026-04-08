require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = require('./db');
const { detectBot } = require('./middleware/botDetect');

const app = express();

app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300, standardHeaders: true });
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts' } });

app.use(limiter);
app.use(express.static(path.join(__dirname, 'public')));

// API Routes
app.use('/api/auth', authLimiter, require('./routes/auth'));
app.use('/api/links', require('./routes/links'));
app.use('/api/admin', require('./routes/admin'));

// Public stats
app.get('/api/stats', async (req, res) => {
  try {
    const links = (await db.getAsync('SELECT COUNT(*) as c FROM links')).c;
    const clicks = (await db.getAsync('SELECT COUNT(*) as c FROM clicks')).c;
    const users = (await db.getAsync('SELECT COUNT(*) as c FROM users')).c;
    res.json({ links, clicks, users });
  } catch (e) { res.json({ links: 0, clicks: 0, users: 0 }); }
});

// Redirect handler - MUST be server-side for proper tracking
app.get('/r/:slug', async (req, res) => {
  const { slug } = req.params;
  try {
    const link = await db.getAsync('SELECT * FROM links WHERE slug = ?', [slug]);
    if (!link) return res.status(404).send('<html><body style="background:#050508;color:#ff2d78;font-family:monospace;text-align:center;padding:4rem"><h1>404 // LINK NOT FOUND</h1><p>This link does not exist in the system.</p><a href="/" style="color:#00ff88">← RETURN TO BASE</a></body></html>');
    if (!link.is_active) return res.status(410).send('<html><body style="background:#050508;color:#ff2d78;font-family:monospace;text-align:center;padding:4rem"><h1>LINK DISABLED</h1><a href="/" style="color:#00ff88">← RETURN TO BASE</a></body></html>');
    if (link.expires_at && new Date(link.expires_at) < new Date()) return res.status(410).send('Link expired');

    if (link.click_limit > 0) {
      const count = (await db.getAsync('SELECT COUNT(*) as c FROM clicks WHERE link_id = ?', [link.id])).c;
      if (count >= link.click_limit) return res.status(410).send('Click limit reached');
    }

    // Bot detection
    const botResult = detectBot(req);
    const ip = (req.headers['x-forwarded-for']?.split(',')[0]?.trim()) || req.ip || '0.0.0.0';

    // Redirect immediately, log async
    res.redirect(302, link.original_url);

    // Async geo + log (non-blocking)
    setImmediate(async () => {
      let geo = { country: 'Unknown', city: 'Unknown', region: 'Unknown', isp: 'Unknown', lat: 0, lon: 0 };
      try {
        const cleanIp = ip.replace('::ffff:', '');
        if (cleanIp !== '127.0.0.1' && cleanIp !== '::1') {
          const geoRes = await fetch(`http://ip-api.com/json/${cleanIp}?fields=country,city,regionName,isp,lat,lon`);
          if (geoRes.ok) {
            const d = await geoRes.json();
            if (d.status !== 'fail') {
              geo = { country: d.country || 'Unknown', city: d.city || 'Unknown', region: d.regionName || 'Unknown', isp: d.isp || 'Unknown', lat: d.lat || 0, lon: d.lon || 0 };
            }
          }
        }
      } catch {}

      try {
        await db.runAsync(`
          INSERT INTO clicks (link_id, ip, country, city, region, isp, latitude, longitude,
            browser, os, device, referrer, user_agent, is_bot, bot_reason, human_score)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          link.id, ip, geo.country, geo.city, geo.region, geo.isp, geo.lat, geo.lon,
          botResult.browser, botResult.os, botResult.device,
          req.headers['referer'] || null,
          req.headers['user-agent'] || null,
          botResult.isBot ? 1 : 0,
          botResult.botReason,
          botResult.humanScore
        ]);
      } catch (e) { console.error('Click log error:', e.message); }
    });

  } catch (e) {
    res.status(500).send('Server error');
  }
});

// Create default admin
async function initAdmin() {
  try {
    const existing = await db.getAsync("SELECT id FROM users WHERE role = 'admin'");
    if (!existing) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 10);
      await db.runAsync(
        "INSERT OR IGNORE INTO users (username, email, password, role) VALUES (?, ?, ?, 'admin')",
        [process.env.ADMIN_USERNAME || 'admin', 'admin@shrinkr.local', hash]
      );
      console.log(`[SHRINKR] Admin created: ${process.env.ADMIN_USERNAME || 'admin'} / ${process.env.ADMIN_PASSWORD || 'admin123'}`);
    }
  } catch (e) { console.error('Admin init error:', e.message); }
}

const PORT = process.env.PORT || 3000;

// Wait for DB to be ready then start
setTimeout(async () => {
  await initAdmin();
  app.listen(PORT, () => {
    console.log(`\n[SHRINKR] ✓ Server running → http://localhost:${PORT}`);
    console.log(`[SHRINKR] ✓ Admin login: ${process.env.ADMIN_USERNAME || 'admin'} / ${process.env.ADMIN_PASSWORD || 'admin123'}`);
    console.log(`[SHRINKR] ✓ Bot detection: ACTIVE`);
    console.log(`[SHRINKR] ✓ Geo tracking: ACTIVE (ip-api.com)\n`);
  });
}, 500);
