import { OpenAPIHono } from "@hono/zod-openapi";
import { swaggerUI } from "@hono/swagger-ui";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import type { Env } from "./types/env";
import { errorHandler } from "./middleware/error-handler";
import { authMiddleware } from "./middleware/auth";
import { securityHeaders } from "./middleware/security-headers";
import { rateLimit } from "./middleware/rate-limit";
import { health } from "./routes/health.routes";
import { auth } from "./routes/auth.routes";
import { usersApp } from "./routes/users.routes";
import { rolesApp } from "./routes/roles.routes";

const FORBIDDEN_IN_PROD = {
  error: { code: "FORBIDDEN", message: "Not available in production" },
} as const;

export function createApp() {
  const app = new OpenAPIHono<Env>({
    defaultHook: (result, c) => {
      if (!result.success) {
        return c.json(
          { error: { code: "VALIDATION_ERROR", message: "Invalid request body" } },
          400,
        );
      }
    },
  });

  app.use("*", logger());
  app.use("*", securityHeaders);
  app.use("*", (c, next) => {
    const corsMiddleware = cors({
      origin: c.env.ENVIRONMENT === "production"
        ? (origin) => {
            const allowed = ["https://yourdomain.com"];
            return allowed.includes(origin) ? origin : null;
          }
        : "*",
      credentials: true,
    });
    return corsMiddleware(c, next);
  });
  app.use("*", authMiddleware);
  app.onError(errorHandler);

  app.use("/auth/*", rateLimit({ limit: 5, windowSeconds: 60 }));
  app.use("/users/*", rateLimit({ limit: 60, windowSeconds: 60 }));
  app.use("/users", rateLimit({ limit: 60, windowSeconds: 60 }));
  app.use("/roles/*", rateLimit({ limit: 60, windowSeconds: 60 }));
  app.use("/roles", rateLimit({ limit: 60, windowSeconds: 60 }));
  app.use("/permissions", rateLimit({ limit: 60, windowSeconds: 60 }));

  app.route("/", health);
  app.route("/", auth);
  app.route("/", usersApp);
  app.route("/", rolesApp);

  app.use("/doc", (c, next) => {
    if (c.env.ENVIRONMENT === "production") {
      return c.json(FORBIDDEN_IN_PROD, 403);
    }
    return next();
  });

  app.doc("/doc", {
    openapi: "3.0.0",
    info: {
      title: "Hono Workers API",
      version: "0.1.0",
      description: "Auth + RBAC backend on Cloudflare Workers",
    },
  });

  app.get("/docs", (c) => {
    if (c.env.ENVIRONMENT === "production") {
      return c.json(FORBIDDEN_IN_PROD, 403);
    }
    return swaggerUI({ url: "/doc" })(c);
  });

  return app;
}
