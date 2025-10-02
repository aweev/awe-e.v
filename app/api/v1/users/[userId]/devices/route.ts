// app/api/v1/users/[userId]/devices/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

export const GET = createApiHandler(
    async (_, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const devices = await userService.getUserDevices(userId);

        return NextResponse.json({ devices });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get user devices',
        description: 'Retrieves all trusted devices for the user',
        tags: ['Users', 'Devices'],
    }
);

const revokeAllSchema = z.object({
    currentDeviceId: z.string().cuid(),
});

export const DELETE = createApiHandler(
    async (_, { params, session, body }) => {
        const { userId } = params;
        const { currentDeviceId } = body;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const count = await userService.revokeAllDevicesExcept(
            userId,
            currentDeviceId,
            session.sub
        );

        return NextResponse.json({
            message: `${count} device(s) revoked successfully`,
            count,
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: revokeAllSchema,
        summary: 'Revoke all devices except current',
        description: 'Revokes trust from all devices except the specified one',
        tags: ['Users', 'Devices'],
    }
);