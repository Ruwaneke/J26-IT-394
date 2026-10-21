/**
 * Script to clear all vulnerability records and activity logs in Neon PostgreSQL.
 * Also cleans legacy local JSON vulnerability record files.
 */
import { NeonDatabaseService } from '../data/neonDatabaseService.js';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
  console.log('🧹 Clearing all vulnerability records in the database...');
  const db = NeonDatabaseService.getInstance();
  const initOk = await db.initialize();
  if (!initOk) {
    console.error('❌ Failed to connect to Neon PostgreSQL database.');
    process.exit(1);
  }

  const result = await db.clearAllVulnerabilityRecords();
  console.log(`✅ Database operation result: ${result.success ? 'SUCCESS' : 'FAILED'}, records removed: ${result.deletedCount}`);

  // Also clean up any legacy local JSON record files if present
  const dataDir = path.resolve(__dirname, '../../src/data');
  const filesToClean = [
    'DEV001_vulnerability_records.json',
    'HishenPerera_vulnerability_records.json',
  ];

  for (const f of filesToClean) {
    const fullPath = path.join(dataDir, f);
    if (fs.existsSync(fullPath)) {
      fs.writeFileSync(fullPath, '[]', 'utf8');
      console.log(`🗑️ Reset local file to empty array: ${f}`);
    }
  }

  console.log('✨ All vulnerability records have been completely cleared.');
  process.exit(0);
}

main().catch(err => {
  console.error('Error executing script:', err);
  process.exit(1);
});
