// app/api/v1/auth/resend-verification/route.ts
import { Locale } from '@/lib/i18n';
import { z } from 'zod';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { getLocaleFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';

const resendVerificationSchema = z.object({
    email: z.string().email('Valid email is required'),
});

export const POST = createApiHandler(
    async (req, { body }) => {
        const locale = getLocaleFromRequest(req) as Locale;
        const { email } = body;

        await authService.resendVerificationEmail(email, locale);

        return NextResponse.json({
            message: 'If a matching account exists, a new verification email has been sent.',
            success: true
        });
    },
    {
        limiter: 'strict',
        bodySchema: resendVerificationSchema,
        summary: 'Resend verification email',
        description: 'Resends a verification email to the user',
        tags: ['Authentication'],
    }
);