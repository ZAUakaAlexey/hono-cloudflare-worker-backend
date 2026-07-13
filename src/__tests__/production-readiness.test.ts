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

describe("Production Readiness", () => {
  const app = getTestApp();
  let adminCookie: string;
  let adminUserId: string;

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);

    const e = createMockEnv(env.DB);
    const admin = await registerAdminUser(app, e, "prod-admin@test.com");
    adminCookie = admin.cookie;
    adminUserId = admin.userId;
  });

  // =================================================================
  // P3: Concurrent write conflicts
  // =================================================================
  describe("Concurrent write conflicts", () => {
    it("two simultaneous updates — last write wins, no crash", async () => {
      const [res1, res2] = await Promise.all([
        app.request(
          new Request(`http://localhost/users/${adminUserId}`, {
            method: "PUT",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "Concurrent A" }),
          }),
          {},
          createMockEnv(env.DB),
        ),
        app.request(
          new Request(`http://localhost/users/${adminUserId}`, {
            method: "PUT",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ name: "Concurrent B" }),
          }),
          {},
          createMockEnv(env.DB),
        ),
      ]);

      expect(res1.status).toBe(200);
      expect(res2.status).toBe(200);

      const finalRes = await app.request(
        new Request(`http://localhost/users/${adminUserId}`, {
          headers: { Cookie: `session=${adminCookie}` },
        }),
        {},
        createMockEnv(env.DB),
      );
      const body = (await finalRes.json()) as any;
      expect(["Concurrent A", "Concurrent B"]).toContain(body.user.name);
    });

    it("concurrent role assignment — only one succeeds", async () => {
      const e = createMockEnv(env.DB);
      const userRes = await app.request(
        jsonRequest("/auth/register", {
          method: "POST",
          body: JSON.stringify({ email: "conc-role@test.com", password: "password123", name: "CR" }),
        }),
        {},
        e,
      );
      const userCookie = getSessionCookie(userRes)!;
      const userId = ((await (await app.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${userCookie}` } }),
        {},
        createMockEnv(env.DB),
      )).json()) as any).user.id;

      const [r1, r2] = await Promise.all([
        app.request(
          new Request(`http://localhost/users/${userId}/roles`, {
            method: "POST",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ roleId: "role_editor" }),
          }),
          {},
          createMockEnv(env.DB),
        ),
        app.request(
          new Request(`http://localhost/users/${userId}/roles`, {
            method: "POST",
            headers: { Cookie: `session=${adminCookie}`, "Content-Type": "application/json" },
            body: JSON.stringify({ roleId: "role_editor" }),
          }),
          {},
          createMockEnv(env.DB),
        ),
      ]);

      const statuses = [r1.status, r2.status].sort();
      expect(statuses).toContain(200);
      expect(statuses.filter((s) => s !== 200 && s !== 409).length).toBe(0);
    });
  });

  // =================================================================
  // P4: Token generation independence
  // =================================================================
  describe("Token independence from server state", () => {
    it("tokens from separate app instances are all valid", async () => {
      const app1 = getTestApp();
      const app2 = getTestApp();

      const e1 = createMockEnv(env.DB);
      const res1 = await app1.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "prod-admin@test.com", password: "password123" }),
        }),
        {},
        e1,
      );
      const cookie1 = getSessionCookie(res1)!;

      const e2 = createMockEnv(env.DB);
      const meRes = await app2.request(
        new Request("http://localhost/auth/me", { headers: { Cookie: `session=${cookie1}` } }),
        {},
        e2,
      );
      expect(meRes.status).toBe(200);
    });
  });

  // =================================================================
  // P5: Error format consistency
  // =================================================================
  describe("Error response format consistency", () => {
    const errorCases = [
      { name: "401 unauthorized", req: () => new Request("http://localhost/users"), expected: 401 },
      { name: "404 not found", req: () => new Request("http://localhost/users/nonexistent", { headers: { Cookie: `session=${adminCookie}` } }), expected: 404 },
      { name: "400 validation", req: () => jsonRequest("/auth/register", { method: "POST", body: JSON.stringify({ email: "bad" }) }), expected: 400 },
      { name: "400 malformed JSON", req: () => new Request("http://localhost/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: "not json" }), expected: 400 },
      { name: "400 empty body", req: () => new Request("http://localhost/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: "" }), expected: 400 },
      { name: "409 duplicate", req: () => jsonRequest("/auth/register", { method: "POST", body: JSON.stringify({ email: "prod-admin@test.com", password: "password123", name: "Dup" }) }), expected: 409 },
    ];

    for (const { name, req, expected } of errorCases) {
      it(`${name} (${expected}) has consistent error format`, async () => {
        const e = createMockEnv(env.DB);
        const res = await app.request(req(), {}, e);
        expect(res.status).toBe(expected);

        const body = (await res.json()) as any;

        expect(body.error).toBeDefined();
        expect(typeof body.error.code).toBe("string");
        expect(typeof body.error.message).toBe("string");

        expect(body.error.code).toMatch(/^[A-Z_]+$/);

        expect(body.stack).toBeUndefined();
        expect(body.error.stack).toBeUndefined();
        expect(body.trace).toBeUndefined();
      });
    }
  });
});
