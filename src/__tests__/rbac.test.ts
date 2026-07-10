import { env } from "cloudflare:workers";
import { describe, it, expect, beforeAll } from "vitest";
import {
  getTestApp,
  createMockEnv,
  applyMigrations,
  applySeed,
  jsonRequest,
  getSessionCookie,
  registerAdminUser,
} from "./setup";

describe("RBAC", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);
  let viewerCookie: string;
  let adminCookie: string;
  let viewerUserId: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const viewerRes = await app.request(
      jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: "viewer@test.com", password: "password123", name: "Viewer" }),
      }),
      {},
      mockEnv,
    );
    viewerCookie = getSessionCookie(viewerRes)!;

    const viewerMe = await app.request(
      new Request("http://localhost/auth/me", { headers: { Cookie: `session=${viewerCookie}` } }),
      {},
      mockEnv,
    );
    viewerUserId = ((await viewerMe.json()) as any).user.id;

    const admin = await registerAdminUser(app, mockEnv, "rbac-admin@test.com");
    adminCookie = admin.cookie;
  });

  describe("Viewer role (read only)", () => {
    it("can list users (users:read)", async () => {
      const req = new Request("http://localhost/users", {
        headers: { Cookie: `session=${viewerCookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });

    it("can list roles (roles:read)", async () => {
      const req = new Request("http://localhost/roles", {
        headers: { Cookie: `session=${viewerCookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });

    it("cannot update user (users:update) -> 403", async () => {
      const req = new Request(`http://localhost/users/${viewerUserId}`, {
        method: "PUT",
        headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "Hacked" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(403);
    });

    it("cannot delete user (users:delete) -> 403", async () => {
      const req = new Request(`http://localhost/users/${viewerUserId}`, {
        method: "DELETE",
        headers: { Cookie: `session=${viewerCookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(403);
    });

    it("cannot create role (roles:create) -> 403", async () => {
      const req = new Request("http://localhost/roles", {
        method: "POST",
        headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "hacker_role" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(403);
    });
  });

  describe("Admin role (full access)", () => {
    it("can update user", async () => {
      const req = new Request(`http://localhost/users/${viewerUserId}`, {
        method: "PUT",
        headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "Updated By Admin" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });

    it("can create role", async () => {
      const req = new Request("http://localhost/roles", {
        method: "POST",
        headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "admin_created_role" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(201);
    });

    it("can delete role", async () => {
      const listRes = await app.request(
        new Request("http://localhost/roles", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        mockEnv,
      );
      const allRoles = (await listRes.json()) as any;
      const target = allRoles.roles.find((r: any) => r.name === "admin_created_role");

      const req = new Request(`http://localhost/roles/${target.id}`, {
        method: "DELETE",
        headers: { Cookie: `session=${adminCookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });
  });
});
