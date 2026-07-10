import { z } from "@hono/zod-openapi";

export const ErrorResponseSchema = z
  .object({
    error: z.object({
      code: z.string().openapi({ example: "UNAUTHORIZED" }),
      message: z.string().openapi({ example: "Unauthorized" }),
    }),
  })
  .openapi("ErrorResponse");

export const MessageResponseSchema = z
  .object({
    message: z.string().openapi({ example: "Operation successful" }),
  })
  .openapi("MessageResponse");
