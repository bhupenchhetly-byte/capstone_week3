// Prints every table (structure + rows) in the terminal - handy for Sprint 3 screenshots.
//   npm run db:show               -> all tables
//   npm run db:show -- users      -> one table only
process.env.JWT_SECRET = process.env.JWT_SECRET || 'show-script-placeholder-not-used';
const { db, driver, DB_FILE } = require('../db');

const only = process.argv[2];
const tables = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all().map(t => t.name);

console.log(`\nDatabase file : ${DB_FILE}`);
console.log(`Driver        : ${driver}`);
console.log(`Tables        : ${tables.join(', ')}\n`);

for (const t of tables) {
  if (only && only !== t) continue;
  const cols = db.prepare(`PRAGMA table_info(${t})`).all()
    .map(c => ({ column: c.name, type: c.type, not_null: c.notnull ? 'YES' : '', primary_key: c.pk ? 'YES' : '' }));
  const count = db.prepare(`SELECT COUNT(*) AS c FROM ${t}`).get().c;
  console.log(`=== TABLE: ${t}  (${count} rows) ===`);
  console.table(cols);
  const rows = db.prepare(`SELECT * FROM ${t}`).all().map(r => {
    const o = { ...r };
    if (o.password_hash) o.password_hash = o.password_hash.slice(0, 12) + '...';
    if (o.message && o.message.length > 40) o.message = o.message.slice(0, 40) + '...';
    return o;
  });
  console.table(rows);
}
