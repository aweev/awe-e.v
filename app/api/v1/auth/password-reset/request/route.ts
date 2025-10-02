// app/api/v1/auth/password-reset/request/route.ts
import { Locale } from '@/lib/i18n';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { getLocaleFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { auditService } from '@/lib/services/audit.service';
import { passwordResetRequestSchema } from '@/lib/schemas/auth.schemas';

export const POST = createApiHandler(
    async (req, { body: { email } }) => {
        const locale = getLocaleFromRequest(req) as Locale;

        // Service call is inside the handler, but we always return a success message
        // to prevent user enumeration.
        await authService.requestPasswordReset(email, locale);

        // Use the audit service to log the event
        auditService.fromRequest(req, AUDIT_ACTIONS.PASSWORD_RESET_REQUESTED, null, {
            locale,
            email: email.replace(/(.{2}).*(@.*)/, '$1***$2') // Partially mask email in logs
        });

        return NextResponse.json({
            message: "If an account with that email exists, a reset link has been sent.",
            success: true
        });
    },
    {
        limiter: 'passwordReset',
        bodySchema: passwordResetRequestSchema,
        summary: 'Request password reset',
        description: 'Sends a password reset email to the user',
        tags: ['Authentication'],
    }
);