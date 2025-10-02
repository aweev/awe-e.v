// app/api/v1/auth/oauth/facebook/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { oauthInitiateSchema } from '@/lib/schemas/auth.schemas';
import { auditService } from '@/lib/services/audit.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { exchangeFacebookCode, getFacebookUserInfo, oauthService } from '@/lib/services/auth/oauth.service';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const facebookCallbackQuerySchema = z.object({
    code: z.string().optional(),
    state: z.string().optional(),
    error: z.string().optional(),
});

// GET - OAuth Callback
export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const { code, state, error } = facebookCallbackQuerySchema.parse(Object.fromEntries(searchParams));

    const ip = getIpFromRequest(request);
    const userAgent = request.headers.get('user-agent');

    if (error) {
        auditService.fromRequest(request, 'oauth_error', null, { provider: 'facebook', error, ip, userAgent });
        return NextResponse.redirect(new URL(`/login?error=oauth_access_denied`, request.url));
    }

    if (!code) {
        auditService.fromRequest(request, 'oauth_missing_code', null, { provider: 'facebook', ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_invalid_response', request.url));
    }

    try {
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/facebook`;
        const { access_token } = await exchangeFacebookCode(code, redirectUri);
        const userInfo = await getFacebookUserInfo(access_token);

        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const normalizedData = {
            email: userInfo.email,
            firstName: userInfo.first_name,
            lastName: userInfo.last_name,
            avatarUrl: userInfo.picture.data.url,
        };

        const { authResponse, refreshToken } = await oauthService.handleLogin('facebook', normalizedData, deviceInfo, ip, userAgent ?? undefined);
        auditService.fromRequest(request, 'oauth_login_success', authResponse.user.id, { provider: 'facebook' });

        const response = NextResponse.redirect(new URL(state ? decodeURIComponent(state) : '/dashboard', request.url));
        response.cookies.set(createSessionCookie(refreshToken));
        return response;
    } catch (err) {
        console.error('Facebook OAuth Callback Error:', err);
        auditService.fromRequest(request, 'oauth_exchange_failed', null, { provider: 'facebook', error: String(err), ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_failed', request.url));
    }
}

// POST - Initiate OAuth
export const POST = createApiHandler(
    async (req, { body }) => {
      
        const clientId = process.env.FACEBOOK_APP_ID;
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/facebook`;

        if (!clientId) {
            auditService.fromRequest(req, 'oauth_config_error', null, { provider: 'facebook', reason: 'FACEBOOK_APP_ID is not configured' });
            throw new Error('OAuth provider is not configured.');
        }

        const authUrl = new URL('https://www.facebook.com/v18.0/dialog/oauth');
        authUrl.searchParams.set('client_id', clientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'email public_profile');

        if (body.returnTo) {
            authUrl.searchParams.set('state', encodeURIComponent(body.returnTo));
        }

        return NextResponse.json({
            url: authUrl.toString(),
            provider: 'facebook'
        });
    },
    {
        limiter: 'global',
        bodySchema: oauthInitiateSchema,
        summary: 'Initiate Facebook OAuth',
        description: 'Starts the Facebook OAuth flow',
        tags: ['Authentication', 'OAuth'],
    }
);