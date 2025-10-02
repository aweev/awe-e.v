// app/api/v1/auth/login/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { loginSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const loginResponseSchema = z.object({
    user: z.object({
        id: z.string(),
        email: z.string(),
        firstName: z.string(),
        lastName: z.string(),
        roles: z.array(z.string()),
        permissions: z.array(z.string()),
        onboardingCompleted: z.boolean(),
    }),
    accessToken: z.string(),
    mfaRequired: z.boolean().optional(),
    mfaToken: z.string().optional(),
    deviceVerificationRequired: z.boolean().optional(),
    deviceId: z.string().optional(),
});

export const POST = createApiHandler(
    async (req, { body: { email, password, rememberMe } }) => {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get('user-agent') || undefined;

        // Parse device information
        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const result = await authService.loginWithPassword(email, password, ip, userAgent, deviceInfo);

        if ('mfaRequired' in result) {
            return NextResponse.json({
                mfaRequired: true,
                mfaToken: result.mfaToken,
            });
        }

        if ('deviceVerificationRequired' in result) {
            return NextResponse.json({
                deviceVerificationRequired: true,
                deviceId: result.deviceId,
            });
        }

        const { authResponse, refreshToken } = result;

        const responsePayload = loginResponseSchema.parse({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
            deviceInfo: deviceInfo,
        });

        const response = NextResponse.json(responsePayload);

        response.cookies.set(createSessionCookie(refreshToken, rememberMe));
        return response;
    },
    {
        limiter: 'auth',
        bodySchema: loginSchema,
        summary: 'User login',
        description: 'Authenticates a user with email and password',
        tags: ['Authentication'],
    }
);