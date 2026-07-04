const pool = require('./db');

async function run() {
  console.log('Waiting for tables to finish creating...');
  await new Promise(resolve => setTimeout(resolve, 2000));

  const res = await pool.query(
    "SELECT table_name FROM information_schema.tables WHERE table_schema='public' ORDER BY table_name"
  );
  console.log('Tables found:', res.rows.map(r => r.table_name));
  process.exit(0);
}

run().catch(err => {
  console.error('Error:', err.message);
  process.exit(1);
});
