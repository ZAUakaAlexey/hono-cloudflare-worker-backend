import { eq, and } from "drizzle-orm";
import { nanoid } from "nanoid";
import type { Database } from "../db";
import { roles, permissions, rolePermissions } from "../db/schema";
import { NotFoundError, ConflictError } from "../utils/errors";

export async function listRoles(db: Database) {
  const roleList = await db
    .select({
      id: roles.id,
      name: roles.name,
      description: roles.description,
      createdAt: roles.createdAt,
    })
    .from(roles);

  return { roles: roleList };
}

export async function getRoleById(db: Database, id: string) {
  const role = await db
    .select({
      id: roles.id,
      name: roles.name,
      description: roles.description,
      createdAt: roles.createdAt,
    })
    .from(roles)
    .where(eq(roles.id, id))
    .get();

  if (!role) {
    throw new NotFoundError("Role not found");
  }

  const perms = await db
    .select({
      id: permissions.id,
      action: permissions.action,
      resource: permissions.resource,
    })
    .from(rolePermissions)
    .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
    .where(eq(rolePermissions.roleId, id));

  return { role: { ...role, permissions: perms } };
}

export async function createRole(
  db: Database,
  input: { name: string; description?: string },
) {
  const existing = await db
    .select({ id: roles.id })
    .from(roles)
    .where(eq(roles.name, input.name))
    .get();

  if (existing) {
    throw new ConflictError("Role name already exists");
  }

  const id = nanoid();
  const now = new Date().toISOString();

  await db.insert(roles).values({
    id,
    name: input.name,
    description: input.description ?? null,
    createdAt: now,
  });

  return getRoleById(db, id);
}

export async function updateRole(
  db: Database,
  id: string,
  input: { name?: string; description?: string },
) {
  const existing = await db.select({ id: roles.id }).from(roles).where(eq(roles.id, id)).get();
  if (!existing) {
    throw new NotFoundError("Role not found");
  }

  if (input.name) {
    const nameTaken = await db
      .select({ id: roles.id })
      .from(roles)
      .where(eq(roles.name, input.name))
      .get();
    if (nameTaken && nameTaken.id !== id) {
      throw new ConflictError("Role name already exists");
    }
  }

  await db.update(roles).set(input).where(eq(roles.id, id));

  return getRoleById(db, id);
}

export async function deleteRole(db: Database, id: string) {
  const existing = await db.select({ id: roles.id }).from(roles).where(eq(roles.id, id)).get();
  if (!existing) {
    throw new NotFoundError("Role not found");
  }

  await db.delete(rolePermissions).where(eq(rolePermissions.roleId, id));
  await db.delete(roles).where(eq(roles.id, id));
}

export async function assignPermission(db: Database, roleId: string, permissionId: string) {
  const role = await db.select({ id: roles.id }).from(roles).where(eq(roles.id, roleId)).get();
  if (!role) {
    throw new NotFoundError("Role not found");
  }

  const perm = await db
    .select({ id: permissions.id })
    .from(permissions)
    .where(eq(permissions.id, permissionId))
    .get();
  if (!perm) {
    throw new NotFoundError("Permission not found");
  }

  const existing = await db
    .select({ roleId: rolePermissions.roleId })
    .from(rolePermissions)
    .where(and(eq(rolePermissions.roleId, roleId), eq(rolePermissions.permissionId, permissionId)))
    .get();
  if (existing) {
    throw new ConflictError("Permission already assigned");
  }

  await db.insert(rolePermissions).values({ roleId, permissionId });

  return getRoleById(db, roleId);
}

export async function removePermission(db: Database, roleId: string, permissionId: string) {
  const existing = await db
    .select({ roleId: rolePermissions.roleId })
    .from(rolePermissions)
    .where(and(eq(rolePermissions.roleId, roleId), eq(rolePermissions.permissionId, permissionId)))
    .get();
  if (!existing) {
    throw new NotFoundError("Permission assignment not found");
  }

  await db
    .delete(rolePermissions)
    .where(and(eq(rolePermissions.roleId, roleId), eq(rolePermissions.permissionId, permissionId)));
}

export async function listPermissions(db: Database) {
  const permList = await db
    .select({
      id: permissions.id,
      action: permissions.action,
      resource: permissions.resource,
    })
    .from(permissions);

  return { permissions: permList };
}
