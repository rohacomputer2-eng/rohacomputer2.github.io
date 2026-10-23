// Run on the shop computer:
//   node reset-password.js                      -> shows all accounts (emails)
//   node reset-password.js EMAIL NEWPASSWORD    -> sets a new password
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'roha.db'));
const [email, pass] = process.argv.slice(2);

if (!email) {
  const rows = db.prepare('SELECT email, role FROM users ORDER BY id').all();
  console.log(rows.length ? 'Accounts:' : 'No accounts yet. Open the website to create the owner account.');
  rows.forEach(r => console.log(' - ' + r.email + '  (' + r.role + ')'));
  console.log('\nTo reset: node reset-password.js EMAIL NEWPASSWORD');
} else if (!pass || pass.length < 6) {
  console.log('Password must be at least 6 characters.');
} else {
  const r = db.prepare('UPDATE users SET hash=? WHERE email=?').run(bcrypt.hashSync(pass, 10), email.toLowerCase().trim());
  console.log(r.changes ? 'Done. New password set for ' + email : 'Email not found. Run: node reset-password.js');
}
