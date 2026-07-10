import { env } from "cloudflare:workers";
import { describe, it, expect } from "vitest";
import { getTestApp, createMockEnv } from "./setup";

describe("Health check", () => {
  const app = getTestApp();
  const mockEnv = createMockEnv(env.DB);

  it("GET /health returns 200 with status ok", async () => {
    const res = await app.request("/health", {}, mockEnv);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.status).toBe("ok");
    expect(body.timestamp).toBeDefined();
  });

  it("GET /nonexistent returns 404", async () => {
    const res = await app.request("/nonexistent", {}, mockEnv);
    expect(res.status).toBe(404);
  });

  it("GET /doc returns OpenAPI JSON with all paths", async () => {
    const res = await app.request("/doc", {}, mockEnv);
    expect(res.status).toBe(200);

    const body = (await res.json()) as any;
    expect(body.openapi).toBe("3.0.0");
    expect(body.info.title).toBe("Hono Workers API");
    expect(body.paths["/health"]).toBeDefined();
    expect(body.paths["/auth/register"]).toBeDefined();
    expect(body.paths["/auth/login"]).toBeDefined();
    expect(body.paths["/auth/logout"]).toBeDefined();
    expect(body.paths["/auth/me"]).toBeDefined();
  });

  it("GET /docs returns Swagger UI HTML", async () => {
    const res = await app.request("/docs", {}, mockEnv);
    expect(res.status).toBe(200);
    expect(res.headers.get("content-type")).toContain("text/html");
  });
});
