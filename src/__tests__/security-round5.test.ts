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

describe("Round 5: Deep Security", () => {
  const app = getTestApp();
  let adminCookie: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    const admin = await registerAdminUser(app, e, "r5-admin@test.com");
    adminCookie = admin.cookie;
  });

  describe("Authorization boundary: role deleted while user logged in", () => {
    it("user loses permissions when their role is deleted", async () => {
      const e1 = createMockEnv(env.DB);
      await app.request(
        new Request("http://localhost/roles", {
          method: "POST",
          headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "temp_role_r5" }),
        }),
        {},
        e1,
      );

      const rolesRes = await app.request(
        new Request("http://localhost/roles", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const roles = (await rolesRes.json()) as any;
      const tempRole = roles.roles.find((r: any) => r.name === "temp_role_r5");

      await app.request(
        new Request(`http://localhost/roles/${tempRole.id}/permissions`, {
          method: "POST",
          headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ permissionId: "perm_users_read" }),
        }),
        {},
        createMockEnv(env.DB),
      );

      const e2 = createMockEnv(env.DB);
      const userRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "temp-user-r5@test.com", password: "password123", name: "Temp" }),
        }),
        {},
        e2,
      );
      const userCookie = getSessionCookie(userRes)!;

      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${userCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const userId = ((await meRes.json()) as any).user.id;

      await env.DB.exec(`DELETE FROM user_roles WHERE user_id = '${userId}'`);
      await env.DB.exec(`INSERT INTO user_roles (user_id, role_id) VALUES ('${userId}', '${tempRole.id}')`);

      const beforeDelete = await app.request(
        new Request("http://localhost/users", { headers: { Cookie: `session=${userCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(beforeDelete.status).toBe(200);

      await app.request(
        new Request(`http://localhost/roles/${tempRole.id}`, {
          method: "DELETE",
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        createMockEnv(env.DB),
      );

      const afterDelete = await app.request(
        new Request("http://localhost/users", { headers: { Cookie: `session=${userCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(afterDelete.status).toBe(403);
    });
  });

  describe("Multiple concurrent sessions", () => {
    it("all sessions for same user are valid simultaneously", async () => {
      const cookies: string[] = [];
      for (let i = 0; i < 3; i++) {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "r5-admin@test.com", password: "password123" }),
          }),
          {},
          e,
        );
        cookies.push(getSessionCookie(res)!);
      }

      for (const cookie of cookies) {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
          {},
          e,
        );
        expect(res.status).toBe(200);
      }
    });

    it("logging out one session does not affect others", async () => {
      const e1 = createMockEnv(env.DB);
      const res1 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "r5-admin@test.com", password: "password123" }),
        }),
        {},
        e1,
      );
      const cookie1 = getSessionCookie(res1)!;

      const e2 = createMockEnv(env.DB);
      const res2 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "r5-admin@test.com", password: "password123" }),
        }),
        {},
        e2,
      );
      const cookie2 = getSessionCookie(res2)!;

      await app.request(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: { Cookie: `session=${cookie1}` },
        }),
        {},
        createMockEnv(env.DB),
      );

      const check1 = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie1}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(check1.status).toBe(401);

      const check2 = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie2}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(check2.status).toBe(200);
    });
  });

  describe("Resource exhaustion via role/permission creation", () => {
    it("handles many roles without error", async () => {
      for (let i = 0; i < 20; i++) {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          new Request("http://localhost/roles", {
            method: "POST",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: `stress_role_${i}` }),
          }),
          {},
          e,
        );
        expect(res.status).toBe(201);
      }

      const e = createMockEnv(env.DB);
      const listRes = await app.request(
        new Request("http://localhost/roles", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        e,
      );
      const body = (await listRes.json()) as any;
      expect(body.roles.length).toBeGreaterThanOrEqual(20);
    });
  });

  describe("JSON edge cases", () => {
    it("rejects BOM (byte order mark) in body", async () => {
      const e = createMockEnv(env.DB);
      const body = new Uint8Array([0xef, 0xbb, 0xbf, ...new TextEncoder().encode('{"email":"bom@test.com","password":"pass12345","name":"BOM"}')]);
      const res = await app.request(
        new Request("http://localhost/auth/register", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
        }),
        {},
        e,
      );
      expect(res.status).not.toBe(500);
    });

    it("rejects empty JSON body", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/login", { method: "POST", body: "" }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("rejects null JSON body", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/login", { method: "POST", body: "null" }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("rejects array JSON body", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/login", { method: "POST", body: "[1,2,3]" }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });
  });

  describe("Cookie edge cases", () => {
    it("malformed cookie name=value format", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: "session" } }),
        {},
        e,
      );
      expect(res.status).toBe(401);
    });

    it("cookie with no value", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: "=value" } }),
        {},
        e,
      );
      expect(res.status).toBe(401);
    });

    it("unicode in cookie value", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: "session=токен" } }),
        {},
        e,
      );
      expect(res.status).toBe(401);
    });
  });
});
