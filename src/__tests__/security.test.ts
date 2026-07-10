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

function freshEnv() {
  return createMockEnv(env.DB);
}

describe("Security Audit", () => {
  const app = getTestApp();
  let adminCookie: string;
  let adminUserId: string;
  let viewerCookie: string;
  let viewerUserId: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = freshEnv();
    const admin = await registerAdminUser(app, e, "sec-admin@test.com");
    adminCookie = admin.cookie;
    adminUserId = admin.userId;

    const viewerRes = await app.request(
      jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email: "sec-viewer@test.com", password: "password123", name: "Viewer" }),
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

  // ============================================================
  // 1. PRIVILEGE ESCALATION
  // ============================================================
  describe("Privilege Escalation", () => {
    it("viewer cannot update another user", async () => {
      const e = freshEnv();
      const req = new Request(`http://localhost/users/${adminUserId}`, {
        method: "PUT",
        headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name: "Hacked Admin" }),
      });
      const res = await app.request(req, {}, e);
      expect(res.status).toBe(403);
    });

    it("viewer cannot delete admin user", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, {
          method: "DELETE",
          headers: { Cookie: `session=${viewerCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("viewer cannot assign roles", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request(`http://localhost/users/${viewerUserId}/roles`, {
          method: "POST",
          headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ roleId: "role_admin" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("viewer cannot create roles", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/roles", {
          method: "POST",
          headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "superadmin" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("viewer cannot delete roles", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/roles/role_viewer", {
          method: "DELETE",
          headers: { Cookie: `session=${viewerCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });

    it("viewer cannot assign permissions to roles", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/roles/role_viewer/permissions", {
          method: "POST",
          headers: { Cookie: `session=${viewerCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ permissionId: "perm_users_delete" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
    });
  });

  // ============================================================
  // 2. AUTHENTICATION BYPASS
  // ============================================================
  describe("Authentication Bypass", () => {
    it("cannot access users without auth", async () => {
      const e = freshEnv();
      const res = await app.request("/users", {}, e);
      expect(res.status).toBe(401);
    });

    it("cannot access roles without auth", async () => {
      const e = freshEnv();
      const res = await app.request("/roles", {}, e);
      expect(res.status).toBe(401);
    });

    it("cannot access permissions without auth", async () => {
      const e = freshEnv();
      const res = await app.request("/permissions", {}, e);
      expect(res.status).toBe(401);
    });

    it("rejects invalid session cookie", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/auth/me", {
          headers: { Cookie: "session=fakecookievalue123" },
        }),
        {},
        e,
      );
      expect(res.status).toBe(401);
    });

    it("rejects empty session cookie", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/auth/me", {
          headers: { Cookie: "session=" },
        }),
        {},
        e,
      );
      expect(res.status).toBe(401);
    });

    it("session invalidated after logout", async () => {
      const e = freshEnv();
      const loginRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "sec-viewer@test.com", password: "password123" }),
        }),
        {},
        e,
      );
      const tempCookie = getSessionCookie(loginRes)!;

      await app.request(
        new Request("http://localhost/auth/logout", {
          method: "POST",
          headers: { Cookie: `session=${tempCookie}` },
        }),
        {},
        e,
      );

      const e2 = freshEnv();
      const meRes = await app.request(
        new Request("http://localhost/auth/me", {
          headers: { Cookie: `session=${tempCookie}` },
        }),
        {},
        e2,
      );
      expect(meRes.status).toBe(401);
    });
  });

  // ============================================================
  // 3. INPUT VALIDATION & INJECTION
  // ============================================================
  describe("Input Validation & Injection", () => {
    it("rejects registration with empty name", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "empty@test.com", password: "password123", name: "" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("rejects registration with invalid email", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "not-email", password: "password123", name: "Test" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("rejects registration with short password", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "short@test.com", password: "123", name: "Test" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("rejects registration with overly long password", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "long@test.com", password: "a".repeat(200), name: "Test" }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(400);
    });

    it("SQL injection in login email does not cause 500", async () => {
      const e = freshEnv();
      const sqlPayloads = [
        "' OR 1=1 --",
        "admin@test.com'; DROP TABLE users; --",
        "\" OR \"\"=\"",
      ];

      for (const payload of sqlPayloads) {
        const res = await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: payload, password: "password123" }),
          }),
          {},
          e,
        );
        expect(res.status).not.toBe(500);
      }
    });

    it("SQL injection in user update does not cause 500", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, {
          method: "PUT",
          headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: "'; DROP TABLE users; --" }),
        }),
        {},
        e,
      );
      expect(res.status).not.toBe(500);
    });

    it("HTML tags stripped from name on registration", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "xss@test.com", password: "password123", name: '<script>alert("xss")</script>' }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(201);
      const xssCookie = getSessionCookie(res)!;
      const e2 = freshEnv();
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${xssCookie}` } }),
        {},
        e2,
      );
      const body = (await meRes.json()) as any;
      expect(body.user.name).toBe('alert("xss")');
      expect(body.user.name).not.toContain("<script>");
    });

    it("HTML tags stripped from name on update", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, {
          method: "PUT",
          headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
          body: JSON.stringify({ name: '<img onerror="alert(1)" src=x>Test' }),
        }),
        {},
        e,
      );
      expect(res.status).toBe(200);
      const body = (await res.json()) as any;
      expect(body.user.name).toBe("Test");
      expect(body.user.name).not.toContain("<img");
    });
  });

  // ============================================================
  // 4. USER ENUMERATION
  // ============================================================
  describe("User Enumeration Prevention", () => {
    it("login returns same error for wrong password and non-existent email", async () => {
      const e1 = freshEnv();
      const wrongPassRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "sec-admin@test.com", password: "wrongpassword" }),
        }),
        {},
        e1,
      );

      const e2 = freshEnv();
      const noUserRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "nonexistent@nowhere.com", password: "password123" }),
        }),
        {},
        e2,
      );

      expect(wrongPassRes.status).toBe(401);
      expect(noUserRes.status).toBe(401);

      const wrongPassBody = (await wrongPassRes.json()) as any;
      const noUserBody = (await noUserRes.json()) as any;
      expect(wrongPassBody.error.message).toBe(noUserBody.error.message);
    });
  });

  // ============================================================
  // 5. RATE LIMITING
  // ============================================================
  describe("Rate Limiting", () => {
    it("enforces rate limit on auth endpoints (5 req/min)", async () => {
      const e = freshEnv();
      let lastStatus = 0;
      for (let i = 0; i < 6; i++) {
        const res = await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "brute@test.com", password: "wrong" }),
            headers: { "x-forwarded-for": "10.0.0.1" },
          }),
          {},
          e,
        );
        lastStatus = res.status;
      }
      expect(lastStatus).toBe(429);
    });

    it("includes Retry-After header on 429", async () => {
      const e = freshEnv();
      let lastRes: Response | null = null;
      for (let i = 0; i < 6; i++) {
        lastRes = await app.request(
          jsonRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ email: "retry@test.com", password: "wrong" }),
            headers: { "x-forwarded-for": "10.0.0.2" },
          }),
          {},
          e,
        );
      }
      expect(lastRes!.status).toBe(429);
      expect(lastRes!.headers.get("retry-after")).toBeDefined();
    });

    it("returns rate limit info headers on normal requests", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "info@test.com", password: "wrong" }),
          headers: { "x-forwarded-for": "10.0.0.3" },
        }),
        {},
        e,
      );
      expect(res.headers.get("x-ratelimit-limit")).toBe("5");
      expect(res.headers.get("x-ratelimit-remaining")).toBeDefined();
    });
  });

  // ============================================================
  // 6. SECURITY HEADERS
  // ============================================================
  describe("Security Headers", () => {
    it("includes X-Frame-Options: DENY", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("x-frame-options")).toBe("DENY");
    });

    it("includes X-Content-Type-Options: nosniff", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    });

    it("includes Referrer-Policy", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("referrer-policy")).toBe("strict-origin-when-cross-origin");
    });

    it("includes Permissions-Policy", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("permissions-policy")).toBeDefined();
    });

    it("API responses return JSON content-type", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("content-type")).toContain("application/json");
    });

    it("does not expose server info", async () => {
      const e = freshEnv();
      const res = await app.request("/health", {}, e);
      expect(res.headers.get("server")).toBeNull();
      expect(res.headers.get("x-powered-by")).toBeNull();
    });
  });

  // ============================================================
  // 7. SESSION SECURITY
  // ============================================================
  describe("Session Security", () => {
    it("session cookie has httpOnly, secure, and SameSite flags", async () => {
      const e = freshEnv();
      const res = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "sec-admin@test.com", password: "password123" }),
        }),
        {},
        e,
      );
      const setCookie = res.headers.get("set-cookie") ?? "";
      expect(setCookie.toLowerCase()).toContain("httponly");
      expect(setCookie.toLowerCase()).toContain("secure");
      expect(setCookie.toLowerCase()).toContain("samesite");
    });

    it("each login creates a unique session token", async () => {
      const e1 = freshEnv();
      const res1 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "sec-admin@test.com", password: "password123" }),
        }),
        {},
        e1,
      );
      const e2 = freshEnv();
      const res2 = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "sec-admin@test.com", password: "password123" }),
        }),
        {},
        e2,
      );

      const cookie1 = getSessionCookie(res1);
      const cookie2 = getSessionCookie(res2);
      expect(cookie1).toBeTruthy();
      expect(cookie2).toBeTruthy();
      expect(cookie1).not.toBe(cookie2);
    });

    it("password not returned in user responses", async () => {
      const e = freshEnv();
      const meRes = await app.request(
        new Request("http://localhost/auth/me", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      const body = (await meRes.json()) as any;
      expect(body.user.password).toBeUndefined();
      expect(body.user.passwordHash).toBeUndefined();
      expect(body.user.password_hash).toBeUndefined();
    });

    it("password not returned in user list", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request("http://localhost/users", {
          headers: { Cookie: `session=${adminCookie}` },
        }),
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
  });

  // ============================================================
  // 8. PASSWORD HASHING
  // ============================================================
  describe("Password Hashing", () => {
    it("same password produces different hashes (unique salt)", async () => {
      const e1 = freshEnv();
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "hash1@test.com", password: "samepassword", name: "H1" }),
        }),
        {},
        e1,
      );
      const e2 = freshEnv();
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "hash2@test.com", password: "samepassword", name: "H2" }),
        }),
        {},
        e2,
      );

      const result = await env.DB.prepare(
        "SELECT password_hash FROM users WHERE email IN ('hash1@test.com', 'hash2@test.com')",
      ).all();

      const hashes = result.results.map((r: any) => r.password_hash);
      expect(hashes.length).toBe(2);
      expect(hashes[0]).not.toBe(hashes[1]);
    });
  });

  // ============================================================
  // 9. DEACTIVATED USER ACCESS
  // ============================================================
  describe("Deactivated User Access", () => {
    it("soft-deleted user cannot login", async () => {
      const e = freshEnv();
      await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "victim@test.com", password: "password123", name: "Victim" }),
        }),
        {},
        e,
      );

      const e2 = freshEnv();
      const victimMe = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "victim@test.com", password: "password123" }),
        }),
        {},
        e2,
      );
      const victimCookie = getSessionCookie(victimMe)!;
      const e3 = freshEnv();
      const meRes = await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${victimCookie}` } }),
        {},
        e3,
      );
      const victimId = ((await meRes.json()) as any).user.id;

      const e4 = freshEnv();
      await app.request(
        new Request(`http://localhost/users/${victimId}`, {
          method: "DELETE",
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e4,
      );

      const e5 = freshEnv();
      const loginRes = await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "victim@test.com", password: "password123" }),
        }),
        {},
        e5,
      );
      expect(loginRes.status).toBe(401);
    });
  });

  // ============================================================
  // 10. SELF-DELETION PROTECTION
  // ============================================================
  describe("Self-Deletion Protection", () => {
    it("admin cannot delete themselves", async () => {
      const e = freshEnv();
      const res = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, {
          method: "DELETE",
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        e,
      );
      expect(res.status).toBe(403);
      const body = (await res.json()) as any;
      expect(body.error.message).toContain("Cannot delete yourself");
    });
  });

  // ============================================================
  // 11. API DOCS EXPOSURE
  // ============================================================
  describe("API Documentation Exposure", () => {
    it("Swagger UI accessible in development", async () => {
      const e = freshEnv();
      const res = await app.request("/docs", {}, e);
      expect(res.status).toBe(200);
    });

    it("Swagger UI blocked in production", async () => {
      const prodEnv = { ...freshEnv(), ENVIRONMENT: "production" };
      const res = await app.request("/docs", {}, prodEnv);
      expect(res.status).toBe(403);
    });
  });
});
