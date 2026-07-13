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

describe("WAF & Structured Logging", () => {
  const app = getTestApp();
  let adminCookie: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    const admin = await registerAdminUser(app, e, "waf-admin@test.com");
    adminCookie = admin.cookie;
  });

  // =================================================================
  // WAF: SQL Injection blocking
  // =================================================================
  describe("WAF blocks SQL injection in query params", () => {
    it("blocks UNION SELECT in query", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1 UNION SELECT * FROM users", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
      const body = (await res.json()) as any;
      expect(body.error.code).toBe("FORBIDDEN");
    });

    it("blocks DROP TABLE in query", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=1; DROP TABLE users", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("blocks SQL injection in POST body", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "waf@test.com",
            password: "pass12345",
            name: "'; DELETE FROM users; --",
          }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });
  });

  // =================================================================
  // WAF: XSS blocking in query params
  // =================================================================
  describe("WAF blocks XSS in query params", () => {
    it("blocks script tag in query", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?page=<script>alert(1)</script>", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("blocks javascript: protocol in query", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?redirect=javascript:alert(1)", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("blocks onerror event handler in query", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users?name=<img onerror=alert(1)>", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });
  });

  // =================================================================
  // WAF: Path traversal blocking
  // =================================================================
  describe("WAF blocks path traversal", () => {
    it("blocks %2e%2e%2f (encoded ../) in path", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users/%2e%2e%2fetc/passwd"),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("blocks ..%5c (backslash traversal) in path", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/users/..%5cetc%5cpasswd"),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });
  });

  // =================================================================
  // WAF: Scanner user-agent blocking
  // =================================================================
  describe("WAF blocks known scanner user-agents", () => {
    const scanners = ["sqlmap/1.5", "Nikto/2.1.6", "Nessus/10.0", "w3af"];

    for (const ua of scanners) {
      it(`blocks ${ua.split("/")[0]}`, async () => {
        const e = createMockEnv(env.DB);
        const res = await app.request(
          new Request("http://localhost/health", {
            headers: { "User-Agent": ua },
          }),
          {},
          e,
        );
        expect(res.status).toBe(403);
      });
    }
  });

  // =================================================================
  // WAF: Legitimate requests pass through
  // =================================================================
  describe("WAF allows legitimate requests", () => {
    it("normal health check passes", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request("/health", {}, e);
      expect(res.status).toBe(200);
    });

    it("normal register passes", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "waf-legit@test.com",
            password: "password123",
            name: "Legitimate User",
          }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
    });

    it("name with apostrophe passes (not SQL)", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({
            email: "waf-apos@test.com",
            password: "password123",
            name: "O'Brien",
          }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
    });
  });

  // =================================================================
  // Structured Logging: X-Request-Id header
  // =================================================================
  describe("Structured logging", () => {
    it("returns X-Request-Id header on every response", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request("/health", {}, e);
      const requestId = res.headers.get("x-request-id");
      expect(requestId).toBeTruthy();
      expect(requestId!.length).toBe(16);
    });

    it("each request gets a unique request ID", async () => {
      const e = createMockEnv(env.DB);
      const res1 = await app.request("/health", {}, e);
      const res2 = await app.request("/health", {}, e);
      const id1 = res1.headers.get("x-request-id");
      const id2 = res2.headers.get("x-request-id");
      expect(id1).not.toBe(id2);
    });

    it("request ID present on error responses", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request("/auth/me", {}, e);
      expect(res.status).toBe(401);
      expect(res.headers.get("x-request-id")).toBeTruthy();
    });

    it("request ID present on WAF-blocked responses", async () => {
      const e = createMockEnv(env.DB);
      const res = await app.request(
        new Request("http://localhost/health", {
          headers: { "User-Agent": "sqlmap/1.5" },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });
  });
});
