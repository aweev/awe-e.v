// app/api/v1/users/[userId]/export/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { NextResponse } from 'next/server';

export const GET = createApiHandler(
    async (_, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const exportData = await userService.exportUserData(userId);

        return NextResponse.json(exportData);
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        summary: 'Export user data',
        description: 'Exports all user data in JSON format (GDPR compliance)',
        tags: ['Users', 'GDPR'],
    }
);