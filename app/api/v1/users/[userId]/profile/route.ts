// app/api/v1/users/[userId]/profile/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { updateProfileSchema } from '@/types/user.types';
import { NextResponse } from 'next/server';

export const PATCH = createApiHandler(
    async (req, { params, session, body }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const updatedProfile = await userService.updateProfile(
            userId,
            body,
            session.sub
        );

        return NextResponse.json({ profile: updatedProfile });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: updateProfileSchema,
        summary: 'Update user profile',
        description: 'Updates specific user profile fields',
        tags: ['Users', 'Profile'],
    }
);

export const GET = createApiHandler(
    async (_, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const completion = await userService.getProfileCompletion(userId);

        return NextResponse.json({ completion });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get profile completion status',
        description: 'Returns profile completion percentage and missing fields',
        tags: ['Users', 'Profile'],
    }
);