import { z } from "@hono/zod-openapi";

export const RegisterSchema = z
  .object({
    email: z.string().email().openapi({ example: "user@example.com" }),
    password: z.string().min(8).max(128).openapi({ example: "securepass123" }),
    name: z.string().min(1).max(100).openapi({ example: "John Doe" }),
  })
  .openapi("RegisterInput");

export const LoginSchema = z
  .object({
    email: z.string().email().openapi({ example: "user@example.com" }),
    password: z.string().min(1).openapi({ example: "securepass123" }),
  })
  .openapi("LoginInput");

export const UserResponseSchema = z
  .object({
    user: z.object({
      id: z.string().openapi({ example: "abc123" }),
      email: z.string().email().openapi({ example: "user@example.com" }),
      name: z.string().openapi({ example: "John Doe" }),
      isActive: z.boolean().openapi({ example: true }),
    }),
  })
  .openapi("UserResponse");

export type RegisterInput = z.infer<typeof RegisterSchema>;
export type LoginInput = z.infer<typeof LoginSchema>;
