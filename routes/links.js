const express = require('express');
const db = require('../db');
const { authMiddleware } = require('../middleware/auth');
const { detectBot } = require('../middleware/botDetect');
const router = express.Router();

function genSlug(len = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let s = '';
  for (let i = 0; i < len; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

async function uniqueSlug() {
  let slug = genSlug();
  while (await db.getAsync('SELECT id FROM links WHERE slug = ?', [slug])) {
    slug = genSlug();
  }
  return slug;
}

// Create link (auth required)
router.post('/', authMiddleware, async (req, res) => {
  let { original_url, slug, title, click_limit, expires_at } = req.body;
  if (!original_url) return res.status(400).json({ error: 'URL required' });
  try { new URL(original_url); } catch { return res.status(400).json({ error: 'Invalid URL format' }); }

  try {
    if (!slug) {
      slug = await uniqueSlug();
    } else {
      slug = slug.replace(/[^a-zA-Z0-9_-]/g, '').substring(0, 30);
      if (await db.getAsync('SELECT id FROM links WHERE slug = ?', [slug]))
        return res.status(409).json({ error: 'Slug already taken' });
    }
    const result = await db.runAsync(
      'INSERT INTO links (user_id, slug, original_url, title, click_limit, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
      [req.user.id, slug, original_url, title || null, click_limit || 0, expires_at || null]
    );
    const link = await db.getAsync('SELECT * FROM links WHERE id = ?', [result.lastID]);
    res.json({ ...link, short_url: `${process.env.BASE_URL}/r/${slug}` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Quick shorten (anonymous)
router.post('/quick', async (req, res) => {
  const { original_url } = req.body;
  if (!original_url) return res.status(400).json({ error: 'URL required' });
  try { new URL(original_url); } catch { return res.status(400).json({ error: 'Invalid URL' }); }
  try {
    const slug = await uniqueSlug();
    await db.runAsync('INSERT INTO links (user_id, slug, original_url) VALUES (NULL, ?, ?)', [slug, original_url]);
    res.json({ slug, short_url: `${process.env.BASE_URL}/r/${slug}` });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get user's links
router.get('/', authMiddleware, async (req, res) => {
  try {
    const links = await db.allAsync(`
      SELECT l.*,
        (SELECT COUNT(*) FROM clicks WHERE link_id = l.id) as total_clicks,
        (SELECT COUNT(*) FROM clicks WHERE link_id = l.id AND is_bot = 0) as human_clicks,
        (SELECT COUNT(*) FROM clicks WHERE link_id = l.id AND is_bot = 1) as bot_clicks,
        (SELECT COUNT(*) FROM clicks WHERE link_id = l.id AND date(clicked_at) = date('now')) as today_clicks
      FROM links l WHERE l.user_id = ? ORDER BY l.created_at DESC
    `, [req.user.id]);
    res.json(links.map(l => ({ ...l, short_url: `${process.env.BASE_URL}/r/${l.slug}` })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Get link analytics
router.get('/:id/analytics', authMiddleware, async (req, res) => {
  try {
    const link = await db.getAsync('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!link) return res.status(404).json({ error: 'Link not found' });

    const clicks = await db.allAsync('SELECT * FROM clicks WHERE link_id = ? ORDER BY clicked_at DESC LIMIT 500', [link.id]);

    const stats = {
      total: clicks.length,
      human: clicks.filter(c => !c.is_bot).length,
      bots: clicks.filter(c => c.is_bot).length,
      unique_ips: new Set(clicks.map(c => c.ip)).size,
      today: clicks.filter(c => c.clicked_at?.startsWith(new Date().toISOString().split('T')[0])).length,
    };

    const countries = {};
    clicks.forEach(c => { if (c.country) countries[c.country] = (countries[c.country] || 0) + 1; });
    const topCountries = Object.entries(countries).sort((a, b) => b[1] - a[1]).slice(0, 10);

    const browsers = {};
    clicks.forEach(c => { if (c.browser) browsers[c.browser] = (browsers[c.browser] || 0) + 1; });
    const topBrowsers = Object.entries(browsers).sort((a, b) => b[1] - a[1]).slice(0, 5);

    const oses = {};
    clicks.forEach(c => { if (c.os) oses[c.os] = (oses[c.os] || 0) + 1; });
    const topOS = Object.entries(oses).sort((a, b) => b[1] - a[1]).slice(0, 5);

    const devices = {};
    clicks.forEach(c => { const d = c.device || 'desktop'; devices[d] = (devices[d] || 0) + 1; });

    const refs = {};
    clicks.forEach(c => { const r = c.referrer || 'Direct'; refs[r] = (refs[r] || 0) + 1; });
    const topReferrers = Object.entries(refs).sort((a, b) => b[1] - a[1]).slice(0, 5);

    res.json({
      link: { ...link, short_url: `${process.env.BASE_URL}/r/${link.slug}` },
      stats, topCountries, topBrowsers, topOS, devices, topReferrers,
      recentClicks: clicks.slice(0, 50),
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Toggle link status
router.patch('/:id/toggle', authMiddleware, async (req, res) => {
  try {
    const link = await db.getAsync('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!link) return res.status(404).json({ error: 'Not found' });
    await db.runAsync('UPDATE links SET is_active = ? WHERE id = ?', [link.is_active ? 0 : 1, link.id]);
    res.json({ success: true, is_active: !link.is_active });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Delete link
router.delete('/:id', authMiddleware, async (req, res) => {
  try {
    const link = await db.getAsync('SELECT * FROM links WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
    if (!link) return res.status(404).json({ error: 'Not found' });
    await db.runAsync('DELETE FROM links WHERE id = ?', [link.id]);
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

module.exports = router;
