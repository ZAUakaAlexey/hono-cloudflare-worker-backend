import { env } from "cloudflare:workers";
import { describe, it, expect, beforeAll } from "vitest";
import {
  getTestApp,
  createMockEnv,
  applyMigrations,
  applySeed,
  registerAdminUser,
} from "./setup";

describe("Roles & Permissions", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);
  let cookie: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const admin = await registerAdminUser(app, mockEnv, "roles@test.com");
    cookie = admin.cookie;
  });

  describe("GET /roles", () => {
    it("returns list of roles", async () => {
      const req = new Request("http://localhost/roles", {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.roles.length).toBe(3);
      const names = body.roles.map((r: any) => r.name);
      expect(names).toContain("admin");
      expect(names).toContain("editor");
      expect(names).toContain("viewer");
    });
  });

  describe("POST /roles", () => {
    it("creates a new role", async () => {
      const req = new Request("http://localhost/roles", {
        method: "POST",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "moderator", description: "Can moderate" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(201);

      const body = (await res.json()) as any;
      expect(body.role.name).toBe("moderator");
      expect(body.role.permissions).toEqual([]);
    });

    it("returns 409 for duplicate name", async () => {
      const req = new Request("http://localhost/roles", {
        method: "POST",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "moderator" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(409);
    });
  });

  describe("GET /roles/:id", () => {
    it("returns role with permissions", async () => {
      const req = new Request("http://localhost/roles/role_admin", {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.role.name).toBe("admin");
      expect(body.role.permissions.length).toBe(8);
    });
  });

  describe("PUT /roles/:id", () => {
    it("updates role description", async () => {
      const req = new Request("http://localhost/roles/role_viewer", {
        method: "PUT",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ description: "Updated viewer" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.role.description).toBe("Updated viewer");
    });
  });

  describe("POST /roles/:id/permissions", () => {
    it("assigns permission to role", async () => {
      const listRes = await app.request(
        new Request("http://localhost/roles", { headers: { Cookie: `session=${cookie}` } }),
        {},
        mockEnv,
      );
      const allRoles = (await listRes.json()) as any;
      const modRole = allRoles.roles.find((r: any) => r.name === "moderator");

      const req = new Request(`http://localhost/roles/${modRole.id}/permissions`, {
        method: "POST",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ permissionId: "perm_users_read" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.role.permissions.length).toBe(1);
    });
  });

  describe("GET /permissions", () => {
    it("returns all permissions", async () => {
      const req = new Request("http://localhost/permissions", {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.permissions.length).toBe(8);
    });
  });

  describe("DELETE /roles/:id", () => {
    it("deletes role", async () => {
      const createRes = await app.request(
        new Request("http://localhost/roles", {
          method: "POST",
          headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "temp_role" }),
        }),
        {},
        mockEnv,
      );
      const created = (await createRes.json()) as any;

      const req = new Request(`http://localhost/roles/${created.role.id}`, {
        method: "DELETE",
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const getRes = await app.request(
        new Request(`http://localhost/roles/${created.role.id}`, {
          headers: { Cookie: `session=${cookie}` },
        }),
        {},
        mockEnv,
      );
      expect(getRes.status).toBe(404);
    });
  });
});
