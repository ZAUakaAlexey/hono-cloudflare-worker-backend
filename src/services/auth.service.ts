import { eq } from "drizzle-orm";
import { nanoid } from "nanoid";
import type { Database } from "../db";
import { users, userRoles } from "../db/schema";
import { createSession, invalidateSession } from "../lib/session";
import { ConflictError, UnauthorizedError, TooManyRequestsError } from "../utils/errors";
import { hashPassword, verifyPassword } from "../utils/password";
import { stripHtmlTags, normalizeEmail } from "../utils/sanitize";
import { isAccountLocked, recordLoginAttempt } from "./audit.service";
import type { RegisterInput, LoginInput } from "../validators/auth.schema";

const DEFAULT_ROLE_ID = "role_viewer";

export async function register(db: Database, input: RegisterInput) {
  const email = normalizeEmail(input.email);

  const existing = await db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.email, email))
    .get();

  if (existing) {
    throw new ConflictError("Registration failed");
  }

  const now = new Date().toISOString();
  const userId = nanoid();
  const passwordHash = await hashPassword(input.password);

  await db.insert(users).values({
    id: userId,
    email,
    passwordHash,
    name: stripHtmlTags(input.name),
    isActive: true,
    createdAt: now,
    updatedAt: now,
  });

  await db.insert(userRoles).values({
    userId,
    roleId: DEFAULT_ROLE_ID,
  });

  return createSession(db, userId);
}

export async function login(db: Database, input: LoginInput, ip?: string) {
  const email = normalizeEmail(input.email);

  const locked = await isAccountLocked(db, email);
  if (locked) {
    throw new TooManyRequestsError("Account temporarily locked due to too many failed attempts");
  }

  const user = await db
    .select()
    .from(users)
    .where(eq(users.email, email))
    .get();

  if (!user || !user.isActive) {
    await recordLoginAttempt(db, email, false, ip);
    throw new UnauthorizedError("Invalid email or password");
  }

  const valid = await verifyPassword(input.password, user.passwordHash);
  if (!valid) {
    await recordLoginAttempt(db, email, false, ip);
    throw new UnauthorizedError("Invalid email or password");
  }

  await recordLoginAttempt(db, email, true, ip);
  return createSession(db, user.id);
}

export async function logout(db: Database, token: string) {
  await invalidateSession(db, token);
}
