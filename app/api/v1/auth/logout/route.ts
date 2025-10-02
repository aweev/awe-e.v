// app/api/v1/auth/logout/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { AUTH_CONFIG } from '@/lib/config/auth.config';
import { authService } from '@/lib/services/auth/auth.service';
import { clearSessionCookie } from '@/lib/services/auth/cookie.service';
import { NextResponse } from 'next/server';

export const POST = createApiHandler(
    async (req) => {
        const refreshTokenFromCookie = req.cookies.get(AUTH_CONFIG.SESSION_COOKIE_NAME)?.value;

        if (refreshTokenFromCookie) {
            await authService.logout(refreshTokenFromCookie);
        }

        const response = NextResponse.json({
            message: 'Logged out successfully.',
            success: true
        });

        response.cookies.set(clearSessionCookie());
        return response;
    },
    {
        auth: { level: 'authenticated' },
        summary: 'User logout',
        description: 'Logs out the current user and clears the session',
        tags: ['Authentication'],
    }
);