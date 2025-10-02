// app/api/v1/users/[userId]/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { PERMISSIONS } from '@/lib/audit/actions';
import { NextResponse } from 'next/server';
import { updateProfileSchema } from '@/types/user.types';
import z from 'zod';

export const GET = createApiHandler(
    async (req, { params, session }) => {
        const userId = Array.isArray(params.userId) ? params.userId[0] : params.userId;

        if (session.sub !== userId) {
            const hasPermission = session.permissions.includes(PERMISSIONS.USERS_READ);
            if (!hasPermission) {
                return NextResponse.json(
                    { error: 'Forbidden', code: 'FORBIDDEN' },
                    { status: 403 }
                );
            }
        }

        const user = await userService.getUserById(userId);

        return NextResponse.json({ user });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get user by ID',
        description: 'Retrieves user information including profile and preferences',
        tags: ['Users'],
    }
);

export const PATCH = createApiHandler(
    async (req, { params, session, body }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const parsed = updateProfileSchema.parse(body);

        const updatedUser = await userService.updateProfile(
            userId,
            parsed,
            session.sub
        );
        return NextResponse.json({ user: updatedUser });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        summary: 'Update user profile',
        description: 'Updates user profile information',
        tags: ['Users'],
    }
);

export const DELETE = createApiHandler(
    async (_, { params, session, body }) => {
        const userId = Array.isArray(params.userId) ? params.userId[0] : params.userId;
        const deleteBodySchema = z.object({ reason: z.string().optional() });
        const { reason } = deleteBodySchema.parse(body);

        if (session.sub !== userId) {
            const hasPermission = session.permissions.includes(PERMISSIONS.USERS_DELETE);
            if (!hasPermission) {
                return NextResponse.json(
                    { error: 'Forbidden', code: 'FORBIDDEN' },
                    { status: 403 }
                );
            }
        }

        await userService.deleteUserAccount(userId, session.sub, reason);

        return NextResponse.json({
            message: 'Account deleted successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        summary: 'Delete user account',
        description: 'Permanently deletes user account and all associated data (GDPR)',
        tags: ['Users'],
    }
);