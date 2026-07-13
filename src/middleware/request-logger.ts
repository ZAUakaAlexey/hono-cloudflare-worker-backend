import { createMiddleware } from "hono/factory";
import type { Env } from "../types/env";

function generateRequestId(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export const requestLogger = createMiddleware<Env>(async (c, next) => {
  const requestId = generateRequestId();
  const start = Date.now();

  c.set("requestId" as never, requestId);
  c.header("X-Request-Id", requestId);

  const method = c.req.method;
  const path = new URL(c.req.url).pathname;
  const ip = c.req.header("cf-connecting-ip") ?? "unknown";
  const ua = c.req.header("user-agent") ?? "";
  const ray = c.req.header("cf-ray") ?? "";

  await next();

  const duration = Date.now() - start;
  const status = c.res.status;
  const userId = c.get("user")?.id ?? null;

  const log = {
    level: status >= 500 ? "error" : status >= 400 ? "warn" : "info",
    requestId,
    method,
    path,
    status,
    duration,
    ip,
    userId,
    userAgent: ua.substring(0, 200),
    cfRay: ray,
    timestamp: new Date().toISOString(),
  };

  if (status >= 500) {
    console.error(JSON.stringify(log));
  } else if (status >= 400) {
    console.warn(JSON.stringify(log));
  } else {
    console.log(JSON.stringify(log));
  }
});
