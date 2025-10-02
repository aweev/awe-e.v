// lib/schemas/auth.schemas.ts 
import { z } from "zod";

export const signUpSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email address.' }),
  password: z.string().min(8, { message: 'Password must be at least 8 characters.' }),
  confirmPassword: z.string(),
})
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

export const loginSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
  password: z.string().min(1, "Password is required."),
  rememberMe: z.boolean().optional(),
});

export const mfaVerifySchema = z.object({
  code: z.string().length(6, "MFA code must be 6 digits.").regex(/^\d{6}$/),
  mfaToken: z.string(),
});

export const passwordResetSchema = z.object({
  oldPassword: z.string().min(8, "Old password must be at least 8 characters long."),
  newPassword: z.string().min(8, "New password must be at least 8 characters long."),
})

export const passwordResetRequestSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
});

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, "Reset token is required."),
  newPassword: z.string().min(8, "New password must be at least 8 characters long."),
  confirmPassword: z.string().min(8, "Password must be at least 8 characters long."),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords do not match.",
  path: ["confirmPassword"],
});

export const sendVerificationSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
});

export const oauthInitiateSchema = z.object({
  returnTo: z.string().optional(),
});

export const resendVerificationSchema = z.object({
  email: z.string().email('Please enter a valid email address.'),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(8, "New password must be at least 8 characters"),
  confirmPassword: z.string().min(1, "Password confirmation is required"),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const verifyDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
  code: z.string().optional(),
});

export const trustDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
});

export const revokeDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
});