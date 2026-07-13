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

/**
 * Security regression tests for all pentest findings (F1-F14).
 * Each test maps to a specific finding to prevent reintroduction.
 */
describe("Security Regression", () => {
  const app = getTestApp();
  let adminCookie: string;
  let adminUserId: string;
  let viewerCookie: string;
  let viewerUserId: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    const admin = await registerAdminUser(app, e, "regr-admin@test.com");
    adminCookie = admin.cookie;
    adminUserId = admin.userId;

    const viewerRes = await app.request(
      jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: "regr-viewer@test.com", password: "password123", name: "Viewer" }),
      }),
      {},
      e,
    );
    viewerCookie = getSessionCookie(viewerRes)!;
    const meRes = await app.request(
      new Request("http://localhost/auth/me", { headers: { Cookie: `session=${viewerCookie}` } }),
      {},
      e,
    );
    viewerUserId = ((await meRes.json()) as any).user.id;
  });

  // =================================================================
  // F1 (HIGH): /doc OpenAPI spec must be blocked in production
  // =================================================================
  describe("F1: OpenAPI doc blocked in production", () => {
    it("/doc returns 403 in production", async () => {
      const prodEnv = { ...createMockEnv(env.DB), ENVIRONMENT: "production" };
      const res = await app.request("/doc", {}, prodEnv);
      expect(res.status).toBe(403);
    });

    it("/docs returns 403 in production", async () => {
      const prodEnv = { ...createMockEnv(env.DB), ENVIRONMENT: "production" };
      const res = await app.request("/docs", {}, prodEnv);
      expect(res.status).toBe(403);
    });

    it("/doc accessible in development", async () => {
      const devEnv = createMockEnv(env.DB);
      const res = await app.request("/doc", {}, devEnv);
      expect(res.status).toBe(200);
    });
  });

  // =================================================================
  // F3 (MEDIUM): Zod validation errors must not leak schema details
  // =================================================================
  describe("F3: Zod errors sanitized", () => {
    it("returns generic error, not Zod details", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: 123, password: true, name: null }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
      const body = (await res.json()) as any;
      expect(body.error.code).toBe("VALIDATION_ERROR");
      expect(body.error.message).toBe("Invalid request body");
      expect(body.error.name).toBeUndefined();
      expect(body.success).toBeUndefined();
    });
  });

  // =================================================================
  // F4 (LOW): Registration must not reveal if email exists
  // =================================================================
  describe("F4: Email enumeration prevention", () => {
    it("duplicate email returns generic message", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "regr-admin@test.com", password: "password123", name: "Dup" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(409);
      const body = (await res.json()) as any;
      expect(body.error.message).not.toContain("already registered");
      expect(body.error.message).toBe("Registration failed");
    });
  });

  // =================================================================
  // F5 (MEDIUM): UTF-7 XSS payloads must be stripped
  // =================================================================
  describe("F5: UTF-7 XSS stripped", () => {
    it("strips +ADw-script+AD4- from name", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "utf7-regr@test.com", password: "password123", name: "+ADw-script+AD4-alert(1)+ADw-/script+AD4-" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
      const cookie = getSessionCookie(res)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await meRes.json()) as any;
      expect(body.user.name).not.toContain("+ADw-");
      expect(body.user.name).not.toContain("<script>");
    });
  });

  // =================================================================
  // F6 (LOW): Email max length 254 (RFC 5321)
  // =================================================================
  describe("F6: Email max length enforced", () => {
    it("rejects email longer than 254 chars", async () => {
      const e = createMockEnv(env.DB);
      const longEmail = "a".repeat(300) + "@test.com";
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: longEmail, password: "password123", name: "Long" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });
  });

  // =================================================================
  // F7 (LOW): Email must be case-insensitive
  // =================================================================
  describe("F7: Case-insensitive email", () => {
    it("login works with different case", async () => {
      const e = createMockEnv(env.DB);
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "CaseRegr@Test.Com", password: "password123", name: "Case" }),
        }),
        {},
        e,
      );
      const loginRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "caseregr@test.com", password: "password123" }),
        }),
        {},
        createMockEnv(env.DB),
      );
      expect(loginRes.status).toBe(200);
    });
  });

  // =================================================================
  // F10 (HIGH): Rate limit must normalize paths
  // =================================================================
  describe("F10: Rate limit path normalization", () => {
    it("encoded path counts toward same rate limit bucket", async () => {
      const e = createMockEnv(env.DB);
      for (let i = 0; i < 5; i++) {
        await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "rl@test.com", password: "wrong" }),
          }),
          {},
          e,
        );
      }
      const res = await app.request(
        jsonRequest("/auth/%6Cogin", {
          method: "POST",
          body: JSON.stringify({ email: "rl@test.com", password: "wrong" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(429);
    });

    it("dot-segment path counts toward same bucket", async () => {
      const e = createMockEnv(env.DB);
      for (let i = 0; i < 5; i++) {
        await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "rl2@test.com", password: "wrong" }),
          }),
          {},
          e,
        );
      }
      const res = await app.request(
        jsonRequest("/auth/./login", {
          method: "POST",
          body: JSON.stringify({ email: "rl2@test.com", password: "wrong" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(429);
    });
  });

  // =================================================================
  // F12 (MEDIUM): Pagination must be bounded
  // =================================================================
  describe("F12: Pagination bounds", () => {
    it("negative page defaults to 1", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=-1&limit=10", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.pagination.page).toBe(1);
    });

    it("huge limit clamped to 100", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1&limit=999999", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.pagination.limit).toBe(100);
    });

    it("NaN page defaults to 1", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=abc&limit=10", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.pagination.page).toBe(1);
    });

    it("NaN limit defaults to 20", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1&limit=abc", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.pagination.limit).toBe(20);
    });
  });

  // =================================================================
  // F13 (LOW): CRLF must be stripped from name
  // =================================================================
  describe("F13: CRLF injection prevention", () => {
    it("strips carriage return and line feed from name", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "crlf-regr@test.com", password: "password123", name: "test\r\nSet-Cookie: evil=true" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
      const cookie = getSessionCookie(res)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await meRes.json()) as any;
      expect(body.user.name).not.toContain("\r");
      expect(body.user.name).not.toContain("\n");
    });
  });

  // =================================================================
  // F8 supplement: Deactivated user session invalidation
  // =================================================================
  describe("Deactivated user session check", () => {
    it("existing session rejected after user deactivation", async () => {
      const e = createMockEnv(env.DB);
      const victimRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "deact-regr@test.com", password: "password123", name: "Victim" }),
        }),
        {},
        e,
      );
      const victimCookie = getSessionCookie(victimRes)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${victimCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const victimId = ((await meRes.json()) as any).user.id;

      await app.request(
        new Request(`http://localhost/users/${victimId}`, {
          method: "DELETE",
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        createMockEnv(env.DB),
      );

      const afterRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${victimCookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      expect(afterRes.status).toBe(401);
    });
  });

  // =================================================================
  // Additional: Race condition — duplicate email registration
  // =================================================================
  describe("Race condition: duplicate email", () => {
    it("only one registration succeeds for same email", async () => {
      const e = createMockEnv(env.DB);
      const body = JSON.stringify({ email: "race-regr@test.com", password: "password123", name: "Race" });

      const [res1, res2] = await Promise.all([
        app.request(jsonRequest("/auth/register", { method: "POST", body }), {}, e),
        app.request(jsonRequest("/auth/register", { method: "POST", body }), {}, e),
      ]);

      const statuses = [res1.status, res2.status].sort();
      expect(statuses).toContain(201);
      expect(statuses.filter((s) => s === 201).length).toBe(1);
    });
  });

  // =================================================================
  // Additional: Mass assignment protection
  // =================================================================
  describe("Mass assignment protection", () => {
    it("extra fields in register are ignored", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "mass-regr@test.com",
            password: "password123",
            name: "Mass",
            isActive: false,
            id: "hacked-id",
            role: "admin",
          }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
      const cookie = getSessionCookie(res)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await meRes.json()) as any;
      expect(body.user.id).not.toBe("hacked-id");
      expect(body.user.isActive).toBe(true);
    });
  });

  // =================================================================
  // Additional: Session uniqueness per login
  // =================================================================
  describe("Session token uniqueness", () => {
    it("two logins produce different tokens", async () => {
      const e1 = createMockEnv(env.DB);
      const res1 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "regr-admin@test.com", password: "password123" }),
        }),
        {},
        e1,
      );
      const e2 = createMockEnv(env.DB);
      const res2 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "regr-admin@test.com", password: "password123" }),
        }),
        {},
        e2,
      );
      const c1 = getSessionCookie(res1);
      const c2 = getSessionCookie(res2);
      expect(c1).toBeTruthy();
      expect(c2).toBeTruthy();
      expect(c1).not.toBe(c2);
    });
  });

  // =================================================================
  // Additional: Password never in responses
  // =================================================================
  describe("Password not exposed", () => {
    it("not in /auth/me", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.user.password).toBeUndefined();
      expect(body.user.passwordHash).toBeUndefined();
      expect(body.user.password_hash).toBeUndefined();
    });

    it("not in /users list", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users", { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      for (const user of body.users) {
        expect(user.password).toBeUndefined();
        expect(user.passwordHash).toBeUndefined();
        expect(user.password_hash).toBeUndefined();
      }
    });

    it("not in /users/:id detail", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, { headers: { Cookie: `session=${adminCookie}` } }),
        {},
        e,
      );
      const body = (await res.json()) as any;
      expect(body.user.password).toBeUndefined();
      expect(body.user.passwordHash).toBeUndefined();
      expect(body.user.password_hash).toBeUndefined();
    });
  });

  // =================================================================
  // Additional: Null byte stripping
  // =================================================================
  describe("Null byte prevention", () => {
    it("strips null bytes from name", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "null-regr@test.com", password: "password123", name: "admin\x00root" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
      const cookie = getSessionCookie(res)!;
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie}` } }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await meRes.json()) as any;
      expect(body.user.name).not.toContain("\x00");
    });
  });
});
