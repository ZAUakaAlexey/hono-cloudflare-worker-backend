import { z } from "@hono/zod-openapi";

export const UserIdParamSchema = z.object({
  id: z.string().openapi({ param: { name: "id", in: "path" }, example: "abc123" }),
});

export const UserRoleParamSchema = z.object({
  id: z.string().openapi({ param: { name: "id", in: "path" }, example: "abc123" }),
  roleId: z.string().openapi({ param: { name: "roleId", in: "path" }, example: "role_editor" }),
});

export const ListUsersQuerySchema = z.object({
  page: z.string().optional().openapi({ param: { name: "page", in: "query" }, example: "1" }),
  limit: z.string().optional().openapi({ param: { name: "limit", in: "query" }, example: "20" }),
});

export const UpdateUserSchema = z
  .object({
    name: z.string().min(1).max(100).optional().openapi({ example: "Jane Doe" }),
    email: z.string().email().optional().openapi({ example: "jane@example.com" }),
  })
  .openapi("UpdateUserInput");

export const AssignRoleSchema = z
  .object({
    roleId: z.string().openapi({ example: "role_editor" }),
  })
  .openapi("AssignRoleInput");

export const UserDetailSchema = z
  .object({
    user: z.object({
      id: z.string().openapi({ example: "abc123" }),
      email: z.string().openapi({ example: "user@example.com" }),
      name: z.string().openapi({ example: "John Doe" }),
      isActive: z.boolean().openapi({ example: true }),
      createdAt: z.string().openapi({ example: "2026-07-10T00:00:00.000Z" }),
      updatedAt: z.string().openapi({ example: "2026-07-10T00:00:00.000Z" }),
      roles: z.array(
        z.object({
          id: z.string().openapi({ example: "role_viewer" }),
          name: z.string().openapi({ example: "viewer" }),
        }),
      ),
    }),
  })
  .openapi("UserDetail");

export const UserListSchema = z
  .object({
    users: z.array(
      z.object({
        id: z.string(),
        email: z.string(),
        name: z.string(),
        isActive: z.boolean(),
        createdAt: z.string(),
      }),
    ),
    pagination: z.object({
      page: z.number(),
      limit: z.number(),
      total: z.number(),
    }),
  })
  .openapi("UserList");
