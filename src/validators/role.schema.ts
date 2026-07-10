import { z } from "@hono/zod-openapi";

export const RoleIdParamSchema = z.object({
  id: z.string().openapi({ param: { name: "id", in: "path" }, example: "role_admin" }),
});

export const RolePermissionParamSchema = z.object({
  id: z.string().openapi({ param: { name: "id", in: "path" }, example: "role_admin" }),
  permissionId: z.string().openapi({ param: { name: "permissionId", in: "path" }, example: "perm_users_read" }),
});

export const CreateRoleSchema = z
  .object({
    name: z.string().min(1).max(50).openapi({ example: "moderator" }),
    description: z.string().max(200).optional().openapi({ example: "Can moderate content" }),
  })
  .openapi("CreateRoleInput");

export const UpdateRoleSchema = z
  .object({
    name: z.string().min(1).max(50).optional().openapi({ example: "moderator" }),
    description: z.string().max(200).optional().openapi({ example: "Updated description" }),
  })
  .openapi("UpdateRoleInput");

export const AssignPermissionSchema = z
  .object({
    permissionId: z.string().openapi({ example: "perm_users_read" }),
  })
  .openapi("AssignPermissionInput");

export const RoleDetailSchema = z
  .object({
    role: z.object({
      id: z.string(),
      name: z.string(),
      description: z.string().nullable(),
      createdAt: z.string(),
      permissions: z.array(
        z.object({
          id: z.string(),
          action: z.string(),
          resource: z.string(),
        }),
      ),
    }),
  })
  .openapi("RoleDetail");

export const RoleListSchema = z
  .object({
    roles: z.array(
      z.object({
        id: z.string(),
        name: z.string(),
        description: z.string().nullable(),
        createdAt: z.string(),
      }),
    ),
  })
  .openapi("RoleList");

export const PermissionListSchema = z
  .object({
    permissions: z.array(
      z.object({
        id: z.string(),
        action: z.string(),
        resource: z.string(),
      }),
    ),
  })
  .openapi("PermissionList");
