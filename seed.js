// Sample data for Sprint 3. Runs automatically on first start when the users table is empty.
// Manual use:  npm run seed          (adds data only if empty)
//              npm run db:reset      (drops all tables and re-seeds)
//
// NOTE: these are DEMO accounts for development only. Change them before any real deployment.
// (seed does not use JWT, but config.js warns if no secret is set - silence that here)
process.env.JWT_SECRET = process.env.JWT_SECRET || 'seed-script-placeholder-not-used';
const bcrypt = require('bcryptjs');
const { db } = require('../db');

const demoUsers = [
  { id: 'usr_001', name: 'Primary Admin',     email: 'admin@group1.com',           password: 'AdminPassCore2026', role: 'Group 1 System Lead' },
  { id: 'usr_002', name: 'Dipesh Giri',       email: 'dipeshgiri@mail.com',        password: 'DipeshSecure2026',  role: 'Administrator' },
  { id: 'usr_003', name: 'Bhupen Budhathoki', email: 'bhupenbudhathoki@mail.com',  password: 'BhupenShield#1',    role: 'Admin 2' },
  { id: 'usr_004', name: 'Aashish Aale',      email: 'aashishaale@mail.com',       password: 'AashishMatrix88',   role: 'Admin 3' },
  { id: 'usr_005', name: 'Sagar Khatri',      email: 'sagarkhatri@mail.com',       password: 'SagarSecure2026',   role: 'Admin 4' },
  { id: 'usr_006', name: 'Roshan Maharjan',   email: 'roshanmaharjan@mail.com',    password: 'RoshanSecure2026',  role: 'Admin 5' },
  { id: 'usr_007', name: 'Dibash Dhamala',    email: 'dibashdhamala@mail.com',     password: 'DibashSecure2026',  role: 'Admin 6' },
];

const sampleTickets = [
  { name: 'Anita Sharma',  email: 'anita.sharma@example.com', message: 'I cannot see my store inventory on the dashboard.', status: 'Open' },
  { name: 'Rohan Thapa',   email: 'rohan.thapa@example.com',  message: 'Can you add a monthly sales report export?',       status: 'In Progress' },
  { name: 'Mina Gurung',   email: 'mina.gurung@example.com',  message: 'How do I reset an employee password?',             status: 'Resolved' },
  { name: 'Sujan Rai',     email: 'sujan.rai@example.com',    message: 'The login page shows an error on my phone.',       status: 'Open' },
  { name: 'Priya Karki',   email: 'priya.karki@example.com',  message: 'Do you support multiple store locations?',         status: 'Open' },
];

function seedIfEmpty() {
  const { count } = db.prepare('SELECT COUNT(*) AS count FROM users').get();
  if (Number(count) > 0) return false;

  const insertUser = db.prepare(
    'INSERT INTO users (id, name, email, password_hash, role) VALUES (?, ?, ?, ?, ?)'
  );
  const insertTicket = db.prepare(
    'INSERT INTO support_tickets (name, email, message, status) VALUES (?, ?, ?, ?)'
  );
  const insertLog = db.prepare(
    'INSERT INTO audit_logs (action, performed_by, user_id) VALUES (?, ?, ?)'
  );

  db.exec('BEGIN');
  try {
    for (const u of demoUsers) {
      insertUser.run(u.id, u.name, u.email, bcrypt.hashSync(u.password, 10), u.role);
    }
    for (const t of sampleTickets) insertTicket.run(t.name, t.email, t.message, t.status);
    insertLog.run('Database initialised and seeded with demo data', 'SYSTEM', null);
    insertLog.run('User Authentication Success: admin@group1.com', 'Primary Admin', 'usr_001');
    insertLog.run('Created User Profile: dibashdhamala@mail.com', 'Primary Admin', 'usr_001');
    db.exec('COMMIT');
  } catch (err) {
    db.exec('ROLLBACK');
    throw err;
  }
  return true;
}

function resetDatabase() {
  db.exec('PRAGMA foreign_keys = OFF;');
  db.exec('DROP TABLE IF EXISTS audit_logs; DROP TABLE IF EXISTS support_tickets; DROP TABLE IF EXISTS users;');
  db.exec('PRAGMA foreign_keys = ON;');
  db.exec(require('fs').readFileSync(require('path').join(__dirname, 'schema.sql'), 'utf8'));
}

module.exports = { seedIfEmpty, resetDatabase };

if (require.main === module) {
  if (process.argv.includes('--reset')) {
    resetDatabase();
    console.log('Tables dropped and recreated.');
  }
  console.log(seedIfEmpty() ? 'Database seeded with demo data.' : 'Database already has data - nothing seeded.');
}
