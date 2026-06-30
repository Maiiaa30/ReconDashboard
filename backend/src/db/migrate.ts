import { migrate } from 'drizzle-orm/better-sqlite3/migrator'
import { resolve } from 'node:path'
import { db } from './index'

// Migrations live in <backend>/drizzle. Both `npm run dev` and the Docker
// container run with the backend root as the working directory.
const migrationsFolder = resolve(process.cwd(), 'drizzle')

// Applies any pending migrations. Safe to run on every boot: already-applied
// migrations are skipped.
export function runMigrations() {
  migrate(db, { migrationsFolder })
}

// Allow running standalone: `npm run db:migrate`
if (process.argv[1]?.endsWith('migrate.ts')) {
  runMigrations()
  console.log('migrations applied')
}
