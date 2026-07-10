import { OpenAPIHono, createRoute } from "@hono/zod-openapi";
import { setCookie, deleteCookie } from "hono/cookie";
import type { Env } from "../types/env";
import { createDb } from "../db";
import { RegisterSchema, LoginSchema, UserResponseSchema } from "../validators/auth.schema";
import { ErrorResponseSchema, MessageResponseSchema } from "../validators/shared.schema";
import * as authService from "../services/auth.service";
import { requireAuth } from "../middleware/auth";

const SESSION_COOKIE = "session";

const registerRoute = createRoute({
  method: "post",
  path: "/auth/register",
  tags: ["Auth"],
  summary: "Register a new user",
  request: {
    body: {
      content: { "application/json": { schema: RegisterSchema } },
      required: true,
    },
  },
  responses: {
    201: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "User registered successfully",
    },
    409: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Email already registered",
    },
    400: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Validation error",
    },
  },
});

const loginRoute = createRoute({
  method: "post",
  path: "/auth/login",
  tags: ["Auth"],
  summary: "Login with email and password",
  request: {
    body: {
      content: { "application/json": { schema: LoginSchema } },
      required: true,
    },
  },
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "Logged in successfully",
    },
    401: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Invalid credentials",
    },
  },
});

const logoutRoute = createRoute({
  method: "post",
  path: "/auth/logout",
  tags: ["Auth"],
  summary: "Logout and invalidate session",
  responses: {
    200: {
      content: { "application/json": { schema: MessageResponseSchema } },
      description: "Logged out successfully",
    },
  },
});

const meRoute = createRoute({
  method: "get",
  path: "/auth/me",
  tags: ["Auth"],
  summary: "Get current authenticated user",
  responses: {
    200: {
      content: { "application/json": { schema: UserResponseSchema } },
      description: "Current user info",
    },
    401: {
      content: { "application/json": { schema: ErrorResponseSchema } },
      description: "Not authenticated",
    },
  },
});

const auth = new OpenAPIHono<Env>();

auth.openapi(registerRoute, async (c) => {
  const input = c.req.valid("json");
  const db = createDb(c.env.DB);
  const { token, expiresAt } = await authService.register(db, input);

  setSessionCookie(c, token, expiresAt);

  return c.json({ message: "Registered successfully" }, 201);
});

auth.openapi(loginRoute, async (c) => {
  const input = c.req.valid("json");
  const db = createDb(c.env.DB);
  const { token, expiresAt } = await authService.login(db, input);

  setSessionCookie(c, token, expiresAt);

  return c.json({ message: "Logged in successfully" });
});

auth.openapi(logoutRoute, async (c) => {
  const token = c.get("sessionToken");
  if (token) {
    const db = createDb(c.env.DB);
    await authService.logout(db, token);
    deleteCookie(c, SESSION_COOKIE, { path: "/" });
  }
  return c.json({ message: "Logged out successfully" });
});

auth.use("/auth/me", requireAuth);
auth.openapi(meRoute, async (c) => {
  const user = c.get("user")!;
  return c.json({ user });
});

function setSessionCookie(c: any, token: string, expiresAt: Date) {
  setCookie(c, SESSION_COOKIE, token, {
    path: "/",
    httpOnly: true,
    secure: true,
    sameSite: "Lax",
    expires: expiresAt,
  });
}

export { auth };
