// app/api/v1/users/[userId]/stats/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const statsQuerySchema = z.object({
    days: z.coerce.number().int().min(1).max(365).optional().default(30),
});

export const GET = createApiHandler(
    async (req, { params, session, query }) => {
        const { userId } = params;
        const { days } = query;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const [stats, activity] = await Promise.all([
            userService.getUserStats(userId),
            userService.getUserActivitySummary(userId, days),
        ]);

        return NextResponse.json({ stats, activity });
    },
    {
        auth: { level: 'authenticated' },
        querySchema: statsQuerySchema,
        summary: 'Get user statistics',
        description: 'Retrieves user statistics and activity summary',
        tags: ['Users', 'Stats'],
    }
);