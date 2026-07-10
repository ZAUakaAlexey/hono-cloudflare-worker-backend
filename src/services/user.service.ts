import { eq, sql, and } from "drizzle-orm";
import type { Database } from "../db";
import { users, userRoles, roles } from "../db/schema";
import { NotFoundError, ConflictError, ForbiddenError } from "../utils/errors";
import { stripHtmlTags } from "../utils/sanitize";

export async function listUsers(
  db: Database,
  page: number,
  limit: number,
) {
  const offset = (page - 1) * limit;

  const [userList, countResult] = await Promise.all([
    db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        isActive: users.isActive,
        createdAt: users.createdAt,
      })
      .from(users)
      .limit(limit)
      .offset(offset),
    db
      .select({ count: sql<number>`count(*)` })
      .from(users)
      .get(),
  ]);

  return {
    users: userList,
    pagination: { page, limit, total: countResult?.count ?? 0 },
  };
}

export async function getUserById(db: Database, id: string) {
  const user = await db
    .select({
      id: users.id,
      email: users.email,
      name: users.name,
      isActive: users.isActive,
      createdAt: users.createdAt,
      updatedAt: users.updatedAt,
    })
    .from(users)
    .where(eq(users.id, id))
    .get();

  if (!user) {
    throw new NotFoundError("User not found");
  }

  const userRoleList = await db
    .select({ id: roles.id, name: roles.name })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(eq(userRoles.userId, id));

  return { user: { ...user, roles: userRoleList } };
}

export async function updateUser(
  db: Database,
  id: string,
  input: { name?: string; email?: string },
) {
  const existing = await db.select({ id: users.id }).from(users).where(eq(users.id, id)).get();
  if (!existing) {
    throw new NotFoundError("User not found");
  }

  if (input.email) {
    const emailTaken = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, input.email))
      .get();
    if (emailTaken && emailTaken.id !== id) {
      throw new ConflictError("Email already taken");
    }
  }

  const sanitized = {
    ...input,
    ...(input.name ? { name: stripHtmlTags(input.name) } : {}),
    updatedAt: new Date().toISOString(),
  };

  await db.update(users).set(sanitized).where(eq(users.id, id));

  return getUserById(db, id);
}

export async function softDeleteUser(db: Database, id: string, currentUserId: string) {
  if (id === currentUserId) {
    throw new ForbiddenError("Cannot delete yourself");
  }

  const existing = await db.select({ id: users.id }).from(users).where(eq(users.id, id)).get();
  if (!existing) {
    throw new NotFoundError("User not found");
  }

  await db
    .update(users)
    .set({ isActive: false, updatedAt: new Date().toISOString() })
    .where(eq(users.id, id));
}

export async function assignRole(db: Database, userId: string, roleId: string) {
  const user = await db.select({ id: users.id }).from(users).where(eq(users.id, userId)).get();
  if (!user) {
    throw new NotFoundError("User not found");
  }

  const role = await db.select({ id: roles.id }).from(roles).where(eq(roles.id, roleId)).get();
  if (!role) {
    throw new NotFoundError("Role not found");
  }

  const existing = await db
    .select({ userId: userRoles.userId })
    .from(userRoles)
    .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)))
    .get();

  if (existing) {
    throw new ConflictError("Role already assigned");
  }

  await db.insert(userRoles).values({ userId, roleId });
  return getUserById(db, userId);
}

export async function removeRole(db: Database, userId: string, roleId: string) {
  const existing = await db
    .select({ userId: userRoles.userId })
    .from(userRoles)
    .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)))
    .get();

  if (!existing) {
    throw new NotFoundError("Role assignment not found");
  }

  await db
    .delete(userRoles)
    .where(and(eq(userRoles.userId, userId), eq(userRoles.roleId, roleId)));
}
