// app/api/v1/users/[userId]/preferences/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { updatePreferencesSchema } from '@/types/user.types';
import { NextResponse } from 'next/server';

export const GET = createApiHandler(
    async (req, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const preferences = await userService.getPreferences(userId);

        return NextResponse.json({ preferences });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get user preferences',
        description: 'Retrieves user preferences with defaults',
        tags: ['Users', 'Preferences'],
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

        const updatedPreferences = await userService.updatePreferences(
            userId,
            body,
            session.sub
        );

        return NextResponse.json({ preferences: updatedPreferences });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: updatePreferencesSchema,
        summary: 'Update user preferences',
        description: 'Updates user notification, theme, and privacy preferences',
        tags: ['Users', 'Preferences'],
    }
);