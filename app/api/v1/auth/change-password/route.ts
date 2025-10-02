// app/api/v1/auth/change-password/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { PasswordPolicyError } from '@/lib/errors/auth.errors';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const changePasswordSchema = z.object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: z.string().min(8, "New password must be at least 8 characters"),
    confirmPassword: z.string().min(1, "Password confirmation is required"),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
});

export const POST = createApiHandler(
    async (req, { session, body: { currentPassword, newPassword } }) => {
        try {
            const ip = getIpFromRequest(req);
            const userAgent = req.headers.get('user-agent') || undefined;

            await authService.changePassword(
                session.sub,
                currentPassword,
                newPassword,
                ip,
                userAgent
            );

            return NextResponse.json({
                message: 'Password changed successfully',
                success: true
            });
        } catch (error) {
            if (error instanceof PasswordPolicyError) {
                return NextResponse.json({
                    error: error.message,
                    code: 'PASSWORD_POLICY_VIOLATION',
                    issues: error.issues,
                }, { status: 400 });
            }

            if (error instanceof Error && error.name === 'AuthError') {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_CURRENT_PASSWORD',
                }, { status: 400 });
            }


            throw error;
        }
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: changePasswordSchema,
        summary: 'Change password',
        description: 'Changes the user password',
        tags: ['Authentication'],
    }
);