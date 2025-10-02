// app/api/v1/auth/password-reset/confirm/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { passwordResetConfirmSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';


export const POST = createApiHandler(
    async (_req, { body: { token, newPassword } }) => {
        try {
            await authService.resetPassword(token, newPassword);
            return NextResponse.json({
                message: "Password has been reset successfully.",
                success: true
            });
        } catch (error) {
            if (error instanceof InvalidTokenError) {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_TOKEN'
                }, { status: 400 });
            }
            throw error;
        }
    },
    {
        limiter: 'strict',
        bodySchema: passwordResetConfirmSchema,
        summary: 'Confirm password reset',
        description: 'Resets a user password using a reset token',
        tags: ['Authentication'],
    }
);