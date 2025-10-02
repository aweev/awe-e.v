// app/api/v1/users/roles/assign/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { PERMISSIONS } from '@/lib/audit/actions';
import { bulkUserOperationSchema } from '@/types/user.types';
import { NextResponse } from 'next/server';

export const POST = createApiHandler(
    async (_, { session, body }) => {
        const result = await userService.bulkAssignRoles(body, session.sub);

        return NextResponse.json(result);
    },
    {
        auth: {
            level: 'authenticated',
            permission: PERMISSIONS.ROLES_ASSIGN
        },
        limiter: 'strict',
        bodySchema: bulkUserOperationSchema,
        summary: 'Bulk assign roles',
        description: 'Assigns a role to multiple users at once',
        tags: ['Users', 'Roles'],
    }
);