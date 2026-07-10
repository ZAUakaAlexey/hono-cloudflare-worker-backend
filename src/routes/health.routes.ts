import { OpenAPIHono, createRoute, z } from "@hono/zod-openapi";
import type { Env } from "../types/env";

const HealthResponseSchema = z
  .object({
    status: z.string().openapi({ example: "ok" }),
    timestamp: z.string().openapi({ example: "2026-07-10T00:00:00.000Z" }),
    environment: z.string().openapi({ example: "development" }),
  })
  .openapi("HealthResponse");

const healthRoute = createRoute({
  method: "get",
  path: "/health",
  tags: ["System"],
  summary: "Health check",
  responses: {
    200: {
      content: { "application/json": { schema: HealthResponseSchema } },
      description: "Service is healthy",
    },
  },
});

const health = new OpenAPIHono<Env>();

health.openapi(healthRoute, (c) => {
  return c.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    environment: c.env.ENVIRONMENT,
  });
});

export { health };
