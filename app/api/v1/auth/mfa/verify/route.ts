// app/api/v1/auth/mfa/verify/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { mfaVerifySchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { verifyMfaToken } from '@/lib/services/auth/jwt.service';
import { NextResponse } from 'next/server';


export const POST = createApiHandler(
    async (req, { body: { code, mfaToken } }) => {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get("user-agent") || undefined;

        const payload = await verifyMfaToken(mfaToken);

        const { authResponse, refreshToken } = await authService.verifyMfaAndLogin(payload.sub, code, ip, userAgent);

        const response = NextResponse.json({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
        });

        response.cookies.set(createSessionCookie(refreshToken));
        return response;
    },
    {
        limiter: 'auth',
        bodySchema: mfaVerifySchema,
        summary: 'Verify MFA code',
        description: 'Verifies a multi-factor authentication code',
        tags: ['Authentication', 'MFA'],
    }
);