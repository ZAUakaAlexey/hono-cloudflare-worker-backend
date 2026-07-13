import type { ErrorHandler } from "hono";
import { HTTPException } from "hono/http-exception";
import type { Env } from "../types/env";
import { AppError } from "../utils/errors";

export const errorHandler: ErrorHandler<Env> = (err, c) => {
  if (err instanceof AppError) {
    return c.json(
      {
        error: {
          code: err.code,
          message: err.message,
        },
      },
      err.statusCode as 400,
    );
  }

  if (err instanceof HTTPException) {
    return c.json(
      {
        error: {
          code: "BAD_REQUEST",
          message: "Invalid request",
        },
      },
      err.status as 400,
    );
  }

  if (err.name === "ZodError" || err.constructor?.name === "ZodError") {
    return c.json(
      {
        error: {
          code: "VALIDATION_ERROR",
          message: "Invalid request body",
        },
      },
      400,
    );
  }

  console.error("Unhandled error:", err);

  return c.json(
    {
      error: {
        code: "INTERNAL_ERROR",
        message: "Internal server error",
      },
    },
    500,
  );
};
