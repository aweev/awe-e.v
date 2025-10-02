// app/api/v1/auth/check-email/route.ts
import { prisma } from '@/lib/db';
import { z } from 'zod';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';

const emailCheckSchema = z.object({
    email: z.string().email('A valid email is required.'),
});

export const POST = createApiHandler(
    async (req, { body: { email } }) => {
        const user = await prisma.user.findFirst({
            where: {
                email: {
                    equals: email,
                    mode: 'insensitive',
                },
                isVerified: true,
            },
        });

        return NextResponse.json({
            available: !user,
            message: !user ? 'Email is available' : 'Email is already taken'
        });
    },
    {
        limiter: 'global',
        bodySchema: emailCheckSchema,
        summary: 'Check email availability',
        description: 'Checks if an email address is available for registration',
        tags: ['Authentication'],
    }
);