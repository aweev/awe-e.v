// app/api/v1/auth/email-status/route.ts
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/db';
import { createApiHandler } from '@/lib/api-handler';

const querySchema = z.object({
    email: z.string().email(),
});

type VerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'NOT_FOUND';

export const GET = createApiHandler(
    async (req, { query }) => {
        const { email } = query;

        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase() },
            select: { isVerified: true },
        });

        let status: VerificationStatus;

        if (!user) {
            status = 'NOT_FOUND';
        } else if (user.isVerified) {
            status = 'VERIFIED';
        } else {
            status = 'UNVERIFIED';
        }

        return NextResponse.json({
            status,
            message: status === 'VERIFIED' ? 'Email is verified' :
                status === 'UNVERIFIED' ? 'Email is not verified' :
                    'Email not found in system'
        });
    },
    {
        limiter: 'strict',
        querySchema,
        summary: 'Check email verification status',
        description: 'Checks the verification status of an email address',
        tags: ['Authentication'],
    }
);