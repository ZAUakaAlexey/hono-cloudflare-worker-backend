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

describe("Auth", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);
  });

  describe("POST /auth/register", () => {
    it("creates a new user and returns 201 with session cookie", async () => {
      const req = jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "password123",
          name: "New User",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(201);

      const body = (await res.json()) as any;
      expect(body.message).toBe("Registered successfully");

      const cookie = getSessionCookie(res);
      expect(cookie).toBeTruthy();
    });

    it("returns 409 for duplicate email", async () => {
      const req = jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "password123",
          name: "Duplicate",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(409);
    });

    it("returns 400 for invalid email", async () => {
      const req = jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: "not-an-email",
          password: "password123",
          name: "Bad Email",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(400);
    });

    it("returns 400 for short password", async () => {
      const req = jsonRequest("/auth/register", {
        method: "POST",
        body: JSON.stringify({
          email: "short@example.com",
          password: "123",
          name: "Short Pass",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(400);
    });
  });

  describe("POST /auth/login", () => {
    it("returns 200 with session cookie for valid credentials", async () => {
      const req = jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "password123",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);

      const cookie = getSessionCookie(res);
      expect(cookie).toBeTruthy();
    });

    it("returns 401 for wrong password", async () => {
      const req = jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "wrongpassword",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(401);
    });

    it("returns 401 for non-existent email", async () => {
      const req = jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "noone@example.com",
          password: "password123",
        }),
      });

      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(401);
    });
  });

  describe("GET /auth/me", () => {
    it("returns user data with valid session cookie", async () => {
      const loginReq = jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "password123",
        }),
      });
      const loginRes = await app.request(loginReq, {}, mockEnv);
      const cookie = getSessionCookie(loginRes);

      const meReq = new Request("http://localhost/auth/me", {
        headers: { Cookie: `session=${cookie}` },
      });
      const meRes = await app.request(meReq, {}, mockEnv);
      expect(meRes.status).toBe(200);

      const body = (await meRes.json()) as any;
      expect(body.user.email).toBe("new@example.com");
      expect(body.user.name).toBe("New User");
    });

    it("returns 401 without cookie", async () => {
      const res = await app.request("/auth/me", {}, mockEnv);
      expect(res.status).toBe(401);
    });

    it("returns 401 with invalid cookie", async () => {
      const req = new Request("http://localhost/auth/me", {
        headers: { Cookie: "session=invalid-token" },
      });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(401);
    });
  });

  describe("POST /auth/logout", () => {
    it("invalidates session and clears cookie", async () => {
      const loginReq = jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: "new@example.com",
          password: "password123",
        }),
      });
      const loginRes = await app.request(loginReq, {}, mockEnv);
      const cookie = getSessionCookie(loginRes);

      const logoutReq = new Request("http://localhost/auth/logout", {
        method: "POST",
        headers: { Cookie: `session=${cookie}` },
      });
      const logoutRes = await app.request(logoutReq, {}, mockEnv);
      expect(logoutRes.status).toBe(200);

      const meReq = new Request("http://localhost/auth/me", {
        headers: { Cookie: `session=${cookie}` },
      });
      const meRes = await app.request(meReq, {}, mockEnv);
      expect(meRes.status).toBe(401);
    });

    it("returns 200 even without cookie", async () => {
      const req = new Request("http://localhost/auth/logout", { method: "POST" });
      const res = await app.request(req, {}, mockEnv);
      expect(res.status).toBe(200);
    });
  });
});
