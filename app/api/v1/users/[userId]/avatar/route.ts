// app/api/v1/users/[userId]/avatar/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const avatarSchema = z.object({
    avatarUrl: z.string().url('Invalid avatar URL'),
});

export const POST = createApiHandler(
    async (req, { params, session, body }) => {
        const { userId } = params;
        const { avatarUrl } = body;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const updatedUser = await userService.updateAvatar(
            userId,
            avatarUrl,
            session.sub
        );

        return NextResponse.json({ user: updatedUser });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: avatarSchema,
        summary: 'Update user avatar',
        description: 'Updates user avatar image URL',
        tags: ['Users', 'Avatar'],
    }
);

export const DELETE = createApiHandler(
    async (_, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        await userService.deleteAvatar(userId, session.sub);

        return NextResponse.json({
            message: 'Avatar deleted successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        summary: 'Delete user avatar',
        description: 'Removes user avatar image',
        tags: ['Users', 'Avatar'],
    }
);