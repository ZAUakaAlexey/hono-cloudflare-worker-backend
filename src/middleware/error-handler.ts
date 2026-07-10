import type { ErrorHandler } from "hono";
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
