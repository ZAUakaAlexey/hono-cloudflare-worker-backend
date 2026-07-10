import { createMiddleware } from "hono/factory";
import { getCookie } from "hono/cookie";
import type { Env } from "../types/env";
import { createDb } from "../db";
import { validateSession } from "../lib/session";

const SESSION_COOKIE = "session";

export const authMiddleware = createMiddleware<Env>(async (c, next) => {
  const token = getCookie(c, SESSION_COOKIE);

  if (!token) {
    c.set("user", null);
    c.set("sessionToken", null);
    return next();
  }

  const db = createDb(c.env.DB);
  const result = await validateSession(db, token);

  if (!result) {
    c.set("user", null);
    c.set("sessionToken", null);
    return next();
  }

  c.set("user", result.user);
  c.set("sessionToken", token);

  return next();
});

export const requireAuth = createMiddleware<Env>(async (c, next) => {
  const user = c.get("user");
  if (!user) {
    return c.json(
      { error: { code: "UNAUTHORIZED", message: "Authentication required" } },
      401,
    );
  }
  return next();
});
