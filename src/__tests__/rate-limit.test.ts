import { env } from "cloudflare:workers";
import { describe, it, expect, beforeAll } from "vitest";
import {
  getTestApp,
  createMockEnv,
  applyMigrations,
  applySeed,
  jsonRequest,
} from "./setup";

describe("Rate Limiting", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);

  beforeAll(async () => {
    await applyMigrations(env.DB);
    await applySeed(env.DB);
  });

  it("returns rate limit headers", async () => {
    const req = jsonRequest("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email: "x@test.com", password: "pass" }),
    });
    const res = await app.request(req, {}, mockEnv);
    expect(res.headers.get("x-ratelimit-limit")).toBe("5");
    expect(res.headers.get("x-ratelimit-remaining")).toBeDefined();
  });

  it("returns 429 after exceeding auth rate limit", async () => {
    const freshEnv = createMockEnv(env.DB);

    for (let i = 0; i < 5; i++) {
      await app.request(
        jsonRequest("/auth/login", {
          method: "POST",
          body: JSON.stringify({ email: "x@test.com", password: "pass" }),
          headers: { "x-forwarded-for": "1.2.3.4" },
        }),
        {},
        freshEnv,
      );
    }

    const res = await app.request(
      jsonRequest("/auth/login", {
        method: "POST",
        body: JSON.stringify({ email: "x@test.com", password: "pass" }),
        headers: { "x-forwarded-for": "1.2.3.4" },
      }),
      {},
      freshEnv,
    );

    expect(res.status).toBe(429);
    expect(res.headers.get("retry-after")).toBeDefined();

    const body = (await res.json()) as any;
    expect(body.error.code).toBe("TOO_MANY_REQUESTS");
  });
});
