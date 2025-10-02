// app/api/v1/auth/verify-device/route.ts (New)
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const verifyDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
    code: z.string().optional(), // If email verification is required
});

export const POST = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        try {
            const ip = getIpFromRequest(req);
            const userAgent = req.headers.get('user-agent') || undefined;

            // Parse device information
            const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

            const result = await authService.verifyDeviceAndLogin(
                session.sub,
                deviceId,
                ip,
                userAgent,
                deviceInfo
            );

            const response = NextResponse.json({
                user: result.authResponse.user,
                accessToken: result.authResponse.accessToken,
                onboardingCompleted: result.authResponse.onboardingCompleted,
                deviceInfo: result.deviceInfo
            });

            response.cookies.set(createSessionCookie(result.refreshToken));
            return response;
        } catch (error) {
            if (error instanceof Error && error.name === 'AuthError') {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_DEVICE',
                }, { status: 400 });
            }

            throw error;
        }
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: verifyDeviceSchema,
        summary: 'Verify device',
        description: 'Verifies a new device and completes login',
        tags: ['Authentication', 'Device Management'],
    }
);