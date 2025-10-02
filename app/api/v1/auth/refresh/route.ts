// app/api/v1/auth/refresh/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { AUTH_CONFIG } from '@/lib/config/auth.config';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { clearSessionCookie, createSessionCookie } from '@/lib/services/auth/cookie.service';
import { NextResponse } from 'next/server';

export const POST = createApiHandler(async (req) => {
    const refreshTokenFromCookie = req.cookies.get(AUTH_CONFIG.SESSION_COOKIE_NAME)?.value;

    if (!refreshTokenFromCookie) {
        throw new InvalidTokenError('Missing session token.');
    }

    try {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get('user-agent') || undefined;

        const { authResponse, refreshToken: newRefreshToken } = await authService.refresh(refreshTokenFromCookie, ip, userAgent);

        const response = NextResponse.json({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
        });

        response.cookies.set(createSessionCookie(newRefreshToken));
        return response;

    } catch (error) {
        if (error instanceof InvalidTokenError) {
            const response = NextResponse.json({
                error: 'Session expired or invalid.',
                code: 'SESSION_EXPIRED'
            }, { status: 401 });

            response.cookies.set(clearSessionCookie());
            return response;
        }
        throw error;
    };
},
    {
        summary: 'Refresh access token',
        description: 'Refreshes the access token using a refresh token',
        tags: ['Authentication'],
    });