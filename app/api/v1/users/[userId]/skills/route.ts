// app/api/v1/users/[userId]/skills/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { skillSchema } from '@/types/user.types';
import { NextResponse } from 'next/server';
import { z } from 'zod';

export const GET = createApiHandler(
    async (req, { params, session }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const skills = await userService.getUserSkills(userId);

        return NextResponse.json({ skills });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get user skills',
        description: 'Retrieves all skills associated with the user',
        tags: ['Users', 'Skills'],
    }
);

export const POST = createApiHandler(
    async (req, { params, session, body }) => {
        const { userId } = params;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const skill = await userService.addOrUpdateSkill(
            userId,
            body,
            session.sub
        );

        return NextResponse.json({ skill });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: skillSchema,
        summary: 'Add or update user skill',
        description: 'Adds a new skill or updates existing skill level',
        tags: ['Users', 'Skills'],
    }
);

const bulkSkillsSchema = z.object({
    skills: z.array(skillSchema).min(1).max(50),
});

export const PUT = createApiHandler(
    async (req, { params, session, body }) => {
        const { userId } = params;
        const { skills } = body;

        if (session.sub !== userId) {
            return NextResponse.json(
                { error: 'Forbidden', code: 'FORBIDDEN' },
                { status: 403 }
            );
        }

        const updatedSkills = await userService.bulkUpdateSkills(
            userId,
            skills,
            session.sub
        );

        return NextResponse.json({ skills: updatedSkills });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: bulkSkillsSchema,
        summary: 'Bulk update user skills',
        description: 'Updates multiple skills at once',
        tags: ['Users', 'Skills'],
    }
);