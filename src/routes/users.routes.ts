import { OpenAPIHono, createRoute } from "@hono/zod-openapi";
import type { Env } from "../types/env";
import { createDb } from "../db";
import { requireAuth } from "../middleware/auth";
import { checkPermission } from "../middleware/rbac";
import {
  UserIdParamSchema,
  UserRoleParamSchema,
  ListUsersQuerySchema,
  UpdateUserSchema,
  AssignRoleSchema,
  UserDetailSchema,
  UserListSchema,
} from "../validators/user.schema";
import { ErrorResponseSchema, MessageResponseSchema } from "../validators/shared.schema";
import * as userService from "../services/user.service";

const listRoute = createRoute({
  method: "get",
  path: "/users",
  tags: ["Users"],
  summary: "List users (paginated)",
  request: { query: ListUsersQuerySchema },
  responses: {
    200: {
      content: { "application/json": { schema: UserListSchema } },
      description: "List of users",
    },
  },
});

const getRoute = createRoute({
  method: "get",
  path: "/users/{id}",
  tags: ["Users"],
  summary: "Get user by ID",
  request: { params: UserIdParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: UserDetailSchema } },
      description: "User details with roles",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "User not found",
    },
  },
});

const updateRoute = createRoute({
  method: "put",
  path: "/users/{id}",
  tags: ["Users"],
  summary: "Update user",
  request: {
    params: UserIdParamSchema,
    body: {
      content: { "application/json": { schema: UpdateUserSchema } },
      required: true,
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: UserDetailSchema } },
      description: "Updated user",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "User not found",
    },
    409: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Email already taken",
    },
  },
});

const deleteRoute = createRoute({
  method: "delete",
  path: "/users/{id}",
  tags: ["Users"],
  summary: "Soft delete user",
  request: { params: UserIdParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "User deactivated",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "User not found",
    },
  },
});

const assignRoleRoute = createRoute({
  method: "post",
  path: "/users/{id}/roles",
  tags: ["Users"],
  summary: "Assign role to user",
  request: {
    params: UserIdParamSchema,
    body: {
      content: { "application/json": { schema: AssignRoleSchema } },
      required: true,
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: UserDetailSchema } },
      description: "Role assigned",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "User or role not found",
    },
    409: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role already assigned",
    },
  },
});

const removeRoleRoute = createRoute({
  method: "delete",
  path: "/users/{id}/roles/{roleId}",
  tags: ["Users"],
  summary: "Remove role from user",
  request: { params: UserRoleParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "Role removed",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role assignment not found",
    },
  },
});

const usersApp = new OpenAPIHono<Env>();

usersApp.use("/users/*", requireAuth);
usersApp.use("/users", requireAuth);

usersApp.openapi(listRoute, async (c) => {
  await checkPermission(c, "users:read");
  const { page = "1", limit = "20" } = c.req.valid("query");
  const parsedPage = Math.max(1, parseInt(page) || 1);
  const parsedLimit = Math.min(100, Math.max(1, parseInt(limit) || 20));
  const db = createDb(c.env.DB);
  const result = await userService.listUsers(db, parsedPage, parsedLimit);
  return c.json(result);
});

usersApp.openapi(getRoute, async (c) => {
  await checkPermission(c, "users:read");
  const { id } = c.req.valid("param");
  const db = createDb(c.env.DB);
  const result = await userService.getUserById(db, id);
  return c.json(result);
});

usersApp.openapi(updateRoute, async (c) => {
  await checkPermission(c, "users:update");
  const { id } = c.req.valid("param");
  const input = c.req.valid("json");
  const db = createDb(c.env.DB);
  const result = await userService.updateUser(db, id, input);
  return c.json(result);
});

usersApp.openapi(deleteRoute, async (c) => {
  await checkPermission(c, "users:delete");
  const { id } = c.req.valid("param");
  const currentUser = c.get("user")!;
  const db = createDb(c.env.DB);
  await userService.softDeleteUser(db, id, currentUser.id);
  return c.json({ message: "User deactivated" });
});

usersApp.openapi(assignRoleRoute, async (c) => {
  await checkPermission(c, "users:update");
  const { id } = c.req.valid("param");
  const { roleId } = c.req.valid("json");
  const db = createDb(c.env.DB);
  const result = await userService.assignRole(db, id, roleId);
  return c.json(result);
});

usersApp.openapi(removeRoleRoute, async (c) => {
  await checkPermission(c, "users:update");
  const { id, roleId } = c.req.valid("param");
  const db = createDb(c.env.DB);
  await userService.removeRole(db, id, roleId);
  return c.json({ message: "Role removed" });
});

export { usersApp };
