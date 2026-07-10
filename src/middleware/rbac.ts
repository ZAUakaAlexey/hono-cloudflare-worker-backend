import { eq } from "drizzle-orm";
import type { Context } from "hono";
import type { Env } from "../types/env";
import { createDb } from "../db";
import { userRoles, rolePermissions, permissions, roles } from "../db/schema";
import { ForbiddenError, UnauthorizedError } from "../utils/errors";

export async function checkPermission(c: Context<Env>, requiredPermission: string) {
  const [resource, action] = requiredPermission.split(":");
  const user = c.get("user");

  if (!user) {
    throw new UnauthorizedError();
  }

  const db = createDb(c.env.DB);

  const userRoleList = await db
    .select({ roleName: roles.name })
    .from(userRoles)
    .innerJoin(roles, eq(userRoles.roleId, roles.id))
    .where(eq(userRoles.userId, user.id));

  if (userRoleList.some((r) => r.roleName === "admin")) {
    return;
  }

  const userPerms = await db
    .select({
      action: permissions.action,
      resource: permissions.resource,
    })
    .from(userRoles)
    .innerJoin(rolePermissions, eq(userRoles.roleId, rolePermissions.roleId))
    .innerJoin(permissions, eq(rolePermissions.permissionId, permissions.id))
    .where(eq(userRoles.userId, user.id));

  const hasPermission = userPerms.some(
    (p) => p.resource === resource && p.action === action,
  );

  if (!hasPermission) {
    throw new ForbiddenError("Insufficient permissions");
  }
}
