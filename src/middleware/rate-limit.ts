import { createMiddleware } from "hono/factory";
import type { Env } from "../types/env";

interface RateLimitOptions {
  limit: number;
  windowSeconds: number;
}

export function rateLimit({ limit, windowSeconds }: RateLimitOptions) {
  return createMiddleware<Env>(async (c, next) => {
    const kv = c.env.KV;
    const ip = c.req.header("cf-connecting-ip") ?? c.req.header("x-forwarded-for") ?? "unknown";
    const path = new URL(c.req.url).pathname;
    const key = `rate:${ip}:${path}`;

    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - windowSeconds;

    const stored = await kv.get(key, "json") as { timestamps: number[] } | null;
    const timestamps = stored?.timestamps.filter((t) => t > windowStart) ?? [];

    if (timestamps.length >= limit) {
      const oldestInWindow = Math.min(...timestamps);
      const retryAfter = oldestInWindow + windowSeconds - now;

      c.header("Retry-After", String(retryAfter));
      return c.json(
        {
          error: {
            code: "TOO_MANY_REQUESTS",
            message: "Rate limit exceeded",
          },
        },
        429,
      );
    }

    timestamps.push(now);
    await kv.put(key, JSON.stringify({ timestamps }), {
      expirationTtl: windowSeconds,
    });

    c.header("X-RateLimit-Limit", String(limit));
    c.header("X-RateLimit-Remaining", String(limit - timestamps.length));

    return next();
  });
}
