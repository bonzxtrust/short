const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const db = new sqlite3.Database(path.join(__dirname, 'shrinkr.db'));

// Promisify helpers
db.runAsync = (sql, params = []) => new Promise((res, rej) => {
  db.run(sql, params, function(err) { err ? rej(err) : res(this); });
});
db.getAsync = (sql, params = []) => new Promise((res, rej) => {
  db.get(sql, params, (err, row) => err ? rej(err) : res(row));
});
db.allAsync = (sql, params = []) => new Promise((res, rej) => {
  db.all(sql, params, (err, rows) => err ? rej(err) : res(rows));
});

// Init tables
db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    is_banned INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now')),
    last_login TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    slug TEXT UNIQUE NOT NULL,
    original_url TEXT NOT NULL,
    title TEXT,
    is_active INTEGER DEFAULT 1,
    click_limit INTEGER DEFAULT 0,
    expires_at TEXT,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS clicks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL,
    ip TEXT,
    country TEXT,
    city TEXT,
    region TEXT,
    isp TEXT,
    latitude REAL,
    longitude REAL,
    browser TEXT,
    os TEXT,
    device TEXT,
    referrer TEXT,
    user_agent TEXT,
    is_bot INTEGER DEFAULT 0,
    bot_reason TEXT,
    human_score REAL DEFAULT 0,
    clicked_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (link_id) REFERENCES links(id) ON DELETE CASCADE
  )`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_links_slug ON links(slug)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_clicks_link_id ON clicks(link_id)`);
  db.run(`CREATE INDEX IF NOT EXISTS idx_clicks_is_bot ON clicks(is_bot)`);
});

module.exports = db;
