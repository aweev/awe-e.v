// app/api/v1/auth/devices/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const trustDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
});

const revokeDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
});

// GET - List user devices
export const GET = createApiHandler(
    async (req, { session }) => {
        const devices = await deviceManagementService.getUserDevices(session.sub);

        return NextResponse.json({
            devices,
            count: devices.length,
        });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'List user devices',
        description: 'Returns a list of devices associated with the user account',
        tags: ['Authentication', 'Device Management'],
    }
);

// POST - Trust a device
export const POST = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        await deviceManagementService.trustDevice(session.sub, deviceId);

        return NextResponse.json({
            message: 'Device trusted successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: trustDeviceSchema,
        summary: 'Trust device',
        description: 'Marks a device as trusted for future logins',
        tags: ['Authentication', 'Device Management'],
    }
);

// DELETE - Revoke a device
export const DELETE = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        await deviceManagementService.revokeDevice(session.sub, deviceId);

        return NextResponse.json({
            message: 'Device revoked successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: revokeDeviceSchema,
        summary: 'Revoke device',
        description: 'Revokes trust from a device',
        tags: ['Authentication', 'Device Management'],
    }
);