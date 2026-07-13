import { env } from "cloudflare:workers";
import { describe, it, expect, beforeAll } from "vitest";
import {
  getTestApp,
  createMockEnv,
  applyMigrations,
  applySeed,
  jsonRequest,
  getSessionCookie,
} from "./setup";

describe("Account Lockout & Audit Log", () => {
  const app = getTestApp();

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    await app.request(
      jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: "lockout@test.com", password: "password123", name: "Lockout" }),
      }),
      {},
      e,
    );
  });

  describe("Account lockout after failed attempts", () => {
    it("allows login with correct password", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "lockout@test.com", password: "password123" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
    });

    it("locks account after 5 failed attempts", async () => {
      for (let i = 0; i < 5; i++) {
        const e = createMockEnv(env.DB);
        await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "lockout@test.com", password: "wrongpassword" }),
          }),
          {},
          e,
        );
      }

      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "lockout@test.com", password: "password123" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(429);
      const body = (await res.json()) as any;
      expect(body.error.message).toContain("locked");
    });
  });

  describe("Audit log records actions", () => {
    it("register creates audit entry", async () => {
      const e = createMockEnv(env.DB);
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "audit1@test.com", password: "password123", name: "Audit" }),
        }),
        {},
        e,
      );

      const result = await env.DB.prepare(
        "SELECT * FROM audit_log WHERE action = 'register' ORDER BY created_at DESC LIMIT 1",
      ).first();

      expect(result).toBeDefined();
      expect(result!.resource).toBe("auth");
    });

    it("login creates audit entry", async () => {
      const e = createMockEnv(env.DB);
      await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "audit1@test.com", password: "password123" }),
        }),
        {},
        e,
      );

      const result = await env.DB.prepare(
        "SELECT * FROM audit_log WHERE action = 'login' ORDER BY created_at DESC LIMIT 1",
      ).first();

      expect(result).toBeDefined();
      expect(result!.resource).toBe("auth");
    });

    it("login attempts are recorded", async () => {
      const result = await env.DB.prepare(
        "SELECT COUNT(*) as count FROM login_attempts WHERE email = 'lockout@test.com'",
      ).first();

      expect((result as any).count).toBeGreaterThan(0);
    });
  });

  describe("Session cleanup", () => {
    it("cleanupExpiredSessions removes old sessions", async () => {
      const { cleanupExpiredSessions } = await import("../services/audit.service");
      const { createDb } = await import("../db");
      const db = createDb(env.DB);

      const user = await env.DB.prepare("SELECT id FROM users LIMIT 1").first() as any;
      await env.DB.exec(
        `INSERT INTO sessions (id, user_id, expires_at, created_at) VALUES ('expired-test', '${user.id}', 0, '2020-01-01T00:00:00.000Z')`,
      );

      await cleanupExpiredSessions(db);

      const check = await env.DB.prepare(
        "SELECT id FROM sessions WHERE id = 'expired-test'",
      ).first();
      expect(check).toBeNull();
    });
  });
});
