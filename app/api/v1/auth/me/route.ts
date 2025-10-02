// app/api/v1/auth/me/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';

export const GET = createApiHandler(
    async (_req, { session }) => {
        const user = await authService.getUserById(session!.sub);

        if (!user) {
            return NextResponse.json({
                error: "User not found.",
                code: 'USER_NOT_FOUND'
            }, { status: 404 });
        }

        return NextResponse.json({
            user,
            session: {
                sub: session!.sub,
                email: session!.email,
                roles: session!.roles,
                permissions: session!.permissions,
                isImpersonating: session!.isImpersonating,
                actAsSub: session!.actAsSub,
            }
        });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get current user',
        description: 'Returns the current authenticated user information',
        tags: ['Authentication'],
    }
);