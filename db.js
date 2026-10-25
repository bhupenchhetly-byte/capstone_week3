// Database connection + schema setup.
// Uses better-sqlite3 (installed by `npm install`). If it cannot be loaded
// (e.g. native build problem), falls back to Node's built-in node:sqlite (Node 22.5+).
const fs = require('fs');
const path = require('path');
const { DB_FILE } = require('./config');

fs.mkdirSync(path.dirname(DB_FILE), { recursive: true });

let db;
let driver;
try {
  const Database = require('better-sqlite3');
  db = new Database(DB_FILE);
  driver = 'better-sqlite3';
} catch (err) {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(DB_FILE);
  driver = 'node:sqlite';
}

db.exec('PRAGMA foreign_keys = ON;');
db.exec(fs.readFileSync(path.join(__dirname, 'database', 'schema.sql'), 'utf8'));

module.exports = { db, driver, DB_FILE };
