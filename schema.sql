-- Capstone B - Sprint 3 : Database schema (SQLite)
-- Database file: data/capstone.db

PRAGMA foreign_keys = ON;

-- 1. Users: people who can log in to the admin dashboard
CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  name          TEXT NOT NULL,
  email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,                 -- bcrypt hash, never plain text
  role          TEXT NOT NULL DEFAULT 'Staff Admin',
  created_at    TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 2. Support tickets: messages sent from the Contact page
CREATE TABLE IF NOT EXISTS support_tickets (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT NOT NULL,
  email      TEXT NOT NULL,
  message    TEXT NOT NULL,
  status     TEXT NOT NULL DEFAULT 'Open'
             CHECK (status IN ('Open', 'In Progress', 'Resolved')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- 3. Audit logs: who did what (linked to users)
CREATE TABLE IF NOT EXISTS audit_logs (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  action       TEXT NOT NULL,
  performed_by TEXT NOT NULL,
  user_id      TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_tickets_status ON support_tickets(status);
