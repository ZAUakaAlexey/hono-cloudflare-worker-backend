import { nanoid } from "nanoid";
import { eq, and, gt, sql } from "drizzle-orm";
import type { Database } from "../db";
import { auditLog, loginAttempts } from "../db/schema";

const LOCKOUT_WINDOW_SECONDS = 900;
const MAX_FAILED_ATTEMPTS = 5;

interface AuditEntry {
  userId?: string | null;
  action: string;
  resource: string;
  resourceId?: string;
  detail?: string;
  ip?: string;
}

export async function log(db: Database, entry: AuditEntry) {
  await db.insert(auditLog).values({
    id: nanoid(),
    userId: entry.userId ?? null,
    action: entry.action,
    resource: entry.resource,
    resourceId: entry.resourceId ?? null,
    detail: entry.detail ?? null,
    ip: entry.ip ?? null,
    createdAt: new Date().toISOString(),
  });
}

export async function recordLoginAttempt(
  db: Database,
  email: string,
  success: boolean,
  ip?: string,
) {
  await db.insert(loginAttempts).values({
    id: nanoid(),
    email,
    success,
    ip: ip ?? null,
    createdAt: new Date().toISOString(),
  });
}

export async function isAccountLocked(db: Database, email: string): Promise<boolean> {
  const windowStart = new Date(Date.now() - LOCKOUT_WINDOW_SECONDS * 1000).toISOString();

  const result = await db
    .select({ count: sql<number>`count(*)` })
    .from(loginAttempts)
    .where(
      and(
        eq(loginAttempts.email, email),
        eq(loginAttempts.success, false),
        gt(loginAttempts.createdAt, windowStart),
      ),
    )
    .get();

  return (result?.count ?? 0) >= MAX_FAILED_ATTEMPTS;
}

export async function cleanupExpiredSessions(db: Database): Promise<number> {
  const now = Math.floor(Date.now() / 1000);

  const result = await db.run(
    sql`DELETE FROM sessions WHERE expires_at <= ${now}`,
  );

  return result.changes ?? 0;
}

export async function cleanupOldLoginAttempts(db: Database): Promise<number> {
  const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

  const result = await db.run(
    sql`DELETE FROM login_attempts WHERE created_at <= ${cutoff}`,
  );

  return result.changes ?? 0;
}

export async function cleanupOldAuditLogs(db: Database, daysToKeep = 90): Promise<number> {
  const cutoff = new Date(Date.now() - daysToKeep * 24 * 60 * 60 * 1000).toISOString();

  const result = await db.run(
    sql`DELETE FROM audit_log WHERE created_at <= ${cutoff}`,
  );

  return result.changes ?? 0;
}
