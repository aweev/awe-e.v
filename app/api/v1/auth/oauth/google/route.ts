// app/api/v1/auth/oauth/google/route.ts (Updated)
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { oauthInitiateSchema } from '@/lib/schemas/auth.schemas';
import { auditService } from '@/lib/services/audit.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { exchangeGoogleCode, getGoogleUserInfo, oauthService } from '@/lib/services/auth/oauth.service';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const googleCallbackQuerySchema = z.object({
    code: z.string().optional(),
    state: z.string().optional(),
    error: z.string().optional(),
});

// GET - OAuth Callback
export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const { code, state, error } = googleCallbackQuerySchema.parse(Object.fromEntries(searchParams));

    const ip = getIpFromRequest(request);
    const userAgent = request.headers.get('user-agent');

    if (error) {
        auditService.fromRequest(request, 'oauth_error', null, { provider: 'google', error, ip, userAgent });
        return NextResponse.redirect(new URL(`/login?error=oauth_access_denied`, request.url));
    }

    if (!code) {
        auditService.fromRequest(request, 'oauth_missing_code', null, { provider: 'google', ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_invalid_response', request.url));
    }

    try {
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/google`;
        const { access_token } = await exchangeGoogleCode(code, redirectUri);
        const userInfo = await getGoogleUserInfo(access_token);

        // Parse device information
        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const normalizedData = {
            email: userInfo.email,
            firstName: userInfo.given_name,
            lastName: userInfo.family_name,
            avatarUrl: userInfo.picture,
        };

        const result = await oauthService.handleLogin('google', normalizedData, deviceInfo, ip, userAgent ?? undefined);
        auditService.fromRequest(request, 'oauth_login_success', result.authResponse.user.id, { provider: 'google' });

        const response = NextResponse.redirect(new URL(state ? decodeURIComponent(state) : '/dashboard', request.url));
        response.cookies.set(createSessionCookie(result.refreshToken));
        return response;

    } catch (err) {
        console.error('Google OAuth Callback Error:', err);
        auditService.fromRequest(request, 'oauth_exchange_failed', null, { provider: 'google', error: String(err), ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_failed', request.url));
    }
}

// POST - Initiate OAuth
export const POST = createApiHandler(
    async (req, { body }) => {
        const clientId = process.env.GOOGLE_CLIENT_ID;
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/google`;

        if (!clientId) {
            auditService.fromRequest(req, 'oauth_config_error', null, { provider: 'google', reason: 'GOOGLE_CLIENT_ID is not configured' });
            throw new Error('OAuth provider is not configured.');
        }

        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.set('client_id', clientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'email profile');
        authUrl.searchParams.set('access_type', 'offline');
        authUrl.searchParams.set('prompt', 'consent');

        if (body.returnTo) {
            authUrl.searchParams.set('state', encodeURIComponent(body.returnTo));
        }

        return NextResponse.json({
            url: authUrl.toString(),
            provider: 'google'
        });
    },
    {
        limiter: 'global',
        bodySchema: oauthInitiateSchema,
        summary: 'Initiate Google OAuth',
        description: 'Starts the Google OAuth flow',
        tags: ['Authentication', 'OAuth'],
    }
);