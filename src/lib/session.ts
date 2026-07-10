import { sha256 } from "@oslojs/crypto/sha2";
import { encodeBase64urlNoPadding } from "@oslojs/encoding";
import { eq } from "drizzle-orm";
import type { Database } from "../db";
import { sessions, users } from "../db/schema";

const SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

export function generateSessionToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return encodeBase64urlNoPadding(bytes);
}

export function hashSessionToken(token: string): string {
  const encoded = new TextEncoder().encode(token);
  const hash = sha256(encoded);
  return encodeBase64urlNoPadding(hash);
}

export async function createSession(db: Database, userId: string) {
  const token = generateSessionToken();
  const id = hashSessionToken(token);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_DURATION_MS);

  await db.insert(sessions).values({
    id,
    userId,
    expiresAt: Math.floor(expiresAt.getTime() / 1000),
    createdAt: now.toISOString(),
  });

  return { token, expiresAt };
}

export async function validateSession(db: Database, token: string) {
  const id = hashSessionToken(token);
  const now = Math.floor(Date.now() / 1000);

  const result = await db
    .select({
      session: sessions,
      user: {
        id: users.id,
        email: users.email,
        name: users.name,
        isActive: users.isActive,
      },
    })
    .from(sessions)
    .innerJoin(users, eq(sessions.userId, users.id))
    .where(eq(sessions.id, id))
    .get();

  if (!result) {
    return null;
  }

  if (result.session.expiresAt <= now) {
    await db.delete(sessions).where(eq(sessions.id, id));
    return null;
  }

  if (!result.user.isActive) {
    return null;
  }

  return { session: result.session, user: result.user };
}

export async function invalidateSession(db: Database, token: string) {
  const id = hashSessionToken(token);
  await db.delete(sessions).where(eq(sessions.id, id));
}
