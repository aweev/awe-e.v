// app/api/v1/users/[userId]/skills/[skillId]/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { NextResponse } from 'next/server';

export const DELETE = createApiHandler(
    async (req, { params, session }) => {
        const userId = Array.isArray(params.userId) ? params.userId[0] : params.userId;
        const skillId = Array.isArray(params.skillId) ? params.skillId[0] : params.skillId;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        await userService.removeSkill(userId, skillId, session.sub);

        return NextResponse.json({
            message: 'Skill removed successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        summary: 'Remove user skill',
        description: 'Removes a skill from user profile',
        tags: ['Users', 'Skills'],
    }
);
