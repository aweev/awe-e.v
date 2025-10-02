// lib/api/docs.ts
import { OpenAPIHono } from '@hono/zod-openapi';
import { z } from 'zod';

export const app = new OpenAPIHono();

// Common schemas
export const ErrorSchema = z.object({
    error: z.string(),
    code: z.string().optional(),
    details: z.any().optional(),
});

export const SuccessSchema = z.object({
    message: z.string(),
    data: z.any().optional(),
});

// Authentication schemas
export const LoginRequestSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

export const LoginResponseSchema = z.object({
    user: z.object({
        id: z.string(),
        email: z.string(),
        firstName: z.string(),
        lastName: z.string(),
        roles: z.array(z.string()),
    }),
    accessToken: z.string(),
    onboardingCompleted: z.boolean(),
});

export const MfaVerifyRequestSchema = z.object({
    code: z.string().length(6),
    mfaToken: z.string(),
});

// Register the documentation
app.doc('/doc', {
    openapi: '3.0.0',
    info: {
        version: '1.0.0',
        title: 'AWE e.V. API',
        description: 'Authentication API for AWE e.V. platform',
    },
    servers: [
        {
            url: 'https://api.awe-ev.org',
            description: 'Production server',
        },
        {
            url: 'http://localhost:3000',
            description: 'Development server',
        },
    ],
    components: {
        securitySchemes: {
            Bearer: {
                type: 'http',
                scheme: 'bearer',
            },
        },
    },
    tags: [
        {
            name: 'Authentication',
            description: 'Authentication endpoints',
        },
    ],
});