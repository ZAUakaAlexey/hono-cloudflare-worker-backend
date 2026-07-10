import { createMiddleware } from "hono/factory";
import type { Env } from "../types/env";

export const securityHeaders = createMiddleware<Env>(async (c, next) => {
  await next();
  c.header("X-Frame-Options", "DENY");
  c.header("X-Content-Type-Options", "nosniff");
  c.header("Referrer-Policy", "strict-origin-when-cross-origin");
  c.header("X-XSS-Protection", "0");
  c.header("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
  if (c.env.ENVIRONMENT === "production") {
    c.header("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    c.header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
  }
});
