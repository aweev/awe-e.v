// lib/config/env.ts
import { z } from 'zod';

const envSchema = z.object({
    NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),

    // Database
    DATABASE_URL: z.string().url(),

    // Redis (for rate limiting & sessions)
    REDIS_URL: z.string().url(),

    // JWT Secrets (MUST be strong in production)
    JWT_ACCESS_SECRET: z.string().min(32),
    JWT_REFRESH_SECRET: z.string().min(32),
    JWT_MFA_SECRET: z.string().min(32),

    // OAuth
    GOOGLE_CLIENT_ID: z.string().optional(),
    GOOGLE_CLIENT_SECRET: z.string().optional(),
    FACEBOOK_APP_ID: z.string().optional(),
    FACEBOOK_APP_SECRET: z.string().optional(),

    // Email
    SMTP_HOST: z.string(),
    SMTP_PORT: z.coerce.number(),
    SMTP_USER: z.string(),
    SMTP_PASSWORD: z.string(),

    // Monitoring
    SENTRY_DSN: z.string().url().optional(),

    // App
    NEXT_PUBLIC_APP_URL: z.string().url(),

    // Feature Flags
    ENABLE_RATE_LIMITING: z.coerce.boolean().default(true),
    ENABLE_ACCOUNT_LOCKING: z.coerce.boolean().default(true),
    ENABLE_DEVICE_TRACKING: z.coerce.boolean().default(true),
});

export const ENV = envSchema.parse(process.env);

// Validate critical production settings
if (ENV.NODE_ENV === 'production') {
    if (ENV.JWT_ACCESS_SECRET.length < 32) {
        throw new Error('JWT_ACCESS_SECRET must be at least 32 characters in production');
    }
    // Add more validation...
}