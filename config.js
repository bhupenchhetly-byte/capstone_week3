// Tiny .env loader (no extra dependency needed).
// Copy .env.example to .env and edit the values. .env is NOT committed to GitHub.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const envPath = path.join(__dirname, '.env');
if (fs.existsSync(envPath)) {
  for (const line of fs.readFileSync(envPath, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
    if (m && !line.trim().startsWith('#') && process.env[m[1]] === undefined) {
      process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
    }
  }
}

let jwtSecret = process.env.JWT_SECRET;
if (!jwtSecret || jwtSecret.length < 16) {
  jwtSecret = crypto.randomBytes(32).toString('hex');
  console.warn('[config] JWT_SECRET missing/too short in .env - using a temporary random one.');
  console.warn('[config] Tokens will stop working on restart. Copy .env.example to .env to fix.');
}

module.exports = {
  PORT: process.env.PORT || 3000,
  JWT_SECRET: jwtSecret,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '2h',
  DB_FILE: process.env.DB_FILE || path.join(__dirname, 'data', 'capstone.db'),
};
