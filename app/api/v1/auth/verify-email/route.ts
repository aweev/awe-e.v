// app/api/v1/auth/verify-email/route.ts
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { z } from 'zod';
import { authService } from '@/lib/services/auth/auth.service';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';

const verifyEmailSchema = z.object({
    token: z.string().min(1, 'Verification token is required'),
});

export const POST = createApiHandler(
    async (_req, { body: { token } }) => {
        try {
            const { authResponse, refreshToken } = await authService.verifyEmail(token);

            const response = NextResponse.json({
                message: 'Email verified successfully.',
                user: authResponse.user,
                accessToken: authResponse.accessToken,
                onboardingCompleted: authResponse.onboardingCompleted,
            });

            response.cookies.set(createSessionCookie(refreshToken));
            return response;
        } catch (error) {
            if (error instanceof InvalidTokenError) {
                return NextResponse.json(
                    {
                        error: error.message,
                        code: 'INVALID_TOKEN'
                    },
                    { status: 400 }
                );
            }
            throw error;
        }
    },
    {
        limiter: 'global',
        bodySchema: verifyEmailSchema,
        summary: 'Verify email address',
        description: 'Verifies a user email address using a verification token',
        tags: ['Authentication'],
    }
);