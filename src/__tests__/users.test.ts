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

describe("Users CRUD", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);
  let cookie: string;
  let userId: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const admin = await registerAdminUser(app, mockEnv, "admin@test.com");
    cookie = admin.cookie;
    userId = admin.userId;
  });

  describe("GET /users", () => {
    it("returns 401 without auth", async () => {
      const res = await app.request("/users", {}, mockEnv);
      expect(res.status).toBe(401);
    });

    it("returns paginated user list", async () => {
      const req = new Request("http://localhost/users", {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.users).toBeInstanceOf(Array);
      expect(body.users.length).toBeGreaterThan(0);
      expect(body.pagination).toBeDefined();
      expect(body.pagination.page).toBe(1);
    });
  });

  describe("GET /users/:id", () => {
    it("returns user with roles", async () => {
      const req = new Request(`http://localhost/users/${userId}`, {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.user.email).toBe("admin@test.com");
      expect(body.user.roles).toBeInstanceOf(Array);
    });

    it("returns 404 for non-existent user", async () => {
      const req = new Request("http://localhost/users/nonexistent", {
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(404);
    });
  });

  describe("PUT /users/:id", () => {
    it("updates user name", async () => {
      const req = new Request(`http://localhost/users/${userId}`, {
        method: "PUT",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "Updated Admin" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      expect(body.user.name).toBe("Updated Admin");
    });
  });

  describe("POST /users/:id/roles", () => {
    it("assigns a role to user", async () => {
      const req = new Request(`http://localhost/users/${userId}/roles`, {
        method: "POST",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ roleId: "role_editor" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const body = (await res.json()) as any;
      const roleNames = body.user.roles.map((r: any) => r.name);
      expect(roleNames).toContain("editor");
    });

    it("returns 409 for duplicate role assignment", async () => {
      const req = new Request(`http://localhost/users/${userId}/roles`, {
        method: "POST",
        headers: { Cookie: `session=${cookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ roleId: "role_editor" }),
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(409);
    });
  });

  describe("DELETE /users/:id/roles/:roleId", () => {
    it("removes role from user", async () => {
      const req = new Request(`http://localhost/users/${userId}/roles/role_editor`, {
        method: "DELETE",
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });
  });

  describe("DELETE /users/:id", () => {
    it("soft deletes user", async () => {
      const registerRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "todelete@test.com", password: "password123", name: "Delete Me" }),
        }),
        {},
        mockEnv,
      );
      const deleteCookie = getSessionCookie(registerRes)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${deleteCookie}` } }),
        {},
        mockEnv,
      );
      const deleteUserId = ((await meRes.json()) as any).user.id;

      const req = new Request(`http://localhost/users/${deleteUserId}`, {
        method: "DELETE",
        headers: { Cookie: `session=${cookie}` },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const getReq = new Request(`http://localhost/users/${deleteUserId}`, {
        headers: { Cookie: `session=${cookie}` },
      });
      const getRes = await app.request(getReq, {}, mockEnv);
      const body = (await getRes.json()) as any;
      expect(body.user.isActive).toBe(false);
    });
  });
});
