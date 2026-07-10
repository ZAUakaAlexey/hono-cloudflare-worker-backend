import { OpenAPIHono, createRoute } from "@hono/zod-openapi";
import type { Env } from "../types/env";
import { createDb } from "../db";
import { requireAuth } from "../middleware/auth";
import { checkPermission } from "../middleware/rbac";
import {
  RoleIdParamSchema,
  RolePermissionParamSchema,
  CreateRoleSchema,
  UpdateRoleSchema,
  AssignPermissionSchema,
  RoleDetailSchema,
  RoleListSchema,
  PermissionListSchema,
} from "../validators/role.schema";
import { ErrorResponseSchema, MessageResponseSchema } from "../validators/shared.schema";
import * as roleService from "../services/role.service";

const listRolesRoute = createRoute({
  method: "get",
  path: "/roles",
  tags: ["Roles"],
  summary: "List all roles",
  responses: {
    200: {
      content: { "application/json": { schema: RoleListSchema } },
      description: "List of roles",
    },
  },
});

const getRoleRoute = createRoute({
  method: "get",
  path: "/roles/{id}",
  tags: ["Roles"],
  summary: "Get role by ID with permissions",
  request: { params: RoleIdParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: RoleDetailSchema } },
      description: "Role details",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role not found",
    },
  },
});

const createRoleRoute = createRoute({
  method: "post",
  path: "/roles",
  tags: ["Roles"],
  summary: "Create a new role",
  request: {
    body: {
      content: { "application/json": { schema: CreateRoleSchema } },
      required: true,
    },
  },
  responses: {
    201: {
      content: { "application/json": { schema: RoleDetailSchema } },
      description: "Role created",
    },
    409: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role name already exists",
    },
  },
});

const updateRoleRoute = createRoute({
  method: "put",
  path: "/roles/{id}",
  tags: ["Roles"],
  summary: "Update role",
  request: {
    params: RoleIdParamSchema,
    body: {
      content: { "application/json": { schema: UpdateRoleSchema } },
      required: true,
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: RoleDetailSchema } },
      description: "Updated role",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role not found",
    },
  },
});

const deleteRoleRoute = createRoute({
  method: "delete",
  path: "/roles/{id}",
  tags: ["Roles"],
  summary: "Delete role",
  request: { params: RoleIdParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "Role deleted",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role not found",
    },
  },
});

const assignPermRoute = createRoute({
  method: "post",
  path: "/roles/{id}/permissions",
  tags: ["Roles"],
  summary: "Assign permission to role",
  request: {
    params: RoleIdParamSchema,
    body: {
      content: { "application/json": { schema: AssignPermissionSchema } },
      required: true,
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: RoleDetailSchema } },
      description: "Permission assigned",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Role or permission not found",
    },
    409: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Permission already assigned",
    },
  },
});

const removePermRoute = createRoute({
  method: "delete",
  path: "/roles/{id}/permissions/{permissionId}",
  tags: ["Roles"],
  summary: "Remove permission from role",
  request: { params: RolePermissionParamSchema },
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "Permission removed",
    },
    404: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Permission assignment not found",
    },
  },
});

const listPermsRoute = createRoute({
  method: "get",
  path: "/permissions",
  tags: ["Permissions"],
  summary: "List all permissions",
  responses: {
    200: {
      content: { "application/json": { schema: PermissionListSchema } },
      description: "List of permissions",
    },
  },
});

const rolesApp = new OpenAPIHono<Env>();

rolesApp.use("/roles/*", requireAuth);
rolesApp.use("/roles", requireAuth);
rolesApp.use("/permissions", requireAuth);

rolesApp.openapi(listRolesRoute, async (c) => {
  await checkPermission(c, "roles:read");
  const db = createDb(c.env.DB);
  return c.json(await roleService.listRoles(db));
});

rolesApp.openapi(getRoleRoute, async (c) => {
  await checkPermission(c, "roles:read");
  const { id } = c.req.valid("param");
  const db = createDb(c.env.DB);
  return c.json(await roleService.getRoleById(db, id));
});

rolesApp.openapi(createRoleRoute, async (c) => {
  await checkPermission(c, "roles:create");
  const input = c.req.valid("json");
  const db = createDb(c.env.DB);
  const result = await roleService.createRole(db, input);
  return c.json(result, 201);
});

rolesApp.openapi(updateRoleRoute, async (c) => {
  await checkPermission(c, "roles:update");
  const { id } = c.req.valid("param");
  const input = c.req.valid("json");
  const db = createDb(c.env.DB);
  return c.json(await roleService.updateRole(db, id, input));
});

rolesApp.openapi(deleteRoleRoute, async (c) => {
  await checkPermission(c, "roles:delete");
  const { id } = c.req.valid("param");
  const db = createDb(c.env.DB);
  await roleService.deleteRole(db, id);
  return c.json({ message: "Role deleted" });
});

rolesApp.openapi(assignPermRoute, async (c) => {
  await checkPermission(c, "roles:update");
  const { id } = c.req.valid("param");
  const { permissionId } = c.req.valid("json");
  const db = createDb(c.env.DB);
  return c.json(await roleService.assignPermission(db, id, permissionId));
});

rolesApp.openapi(removePermRoute, async (c) => {
  await checkPermission(c, "roles:update");
  const { id, permissionId } = c.req.valid("param");
  const db = createDb(c.env.DB);
  await roleService.removePermission(db, id, permissionId);
  return c.json({ message: "Permission removed" });
});

rolesApp.openapi(listPermsRoute, async (c) => {
  await checkPermission(c, "roles:read");
  const db = createDb(c.env.DB);
  return c.json(await roleService.listPermissions(db));
});

export { rolesApp };
