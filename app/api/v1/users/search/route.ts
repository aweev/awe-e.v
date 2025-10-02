// app/api/v1/users/search/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { userService } from '@/lib/services/user/user.service';
import { PERMISSIONS } from '@/lib/audit/actions';
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { Role } from '@prisma/client';

const searchQuerySchema = z.object({
    q: z.string().optional(),
    role: z.array(z.nativeEnum(Role)).optional(),
    skills: z.array(z.string()).optional(),
    location: z.string().optional(),
    isActive: z.coerce.boolean().optional(),
    isVerified: z.coerce.boolean().optional(),
    page: z.coerce.number().int().min(1).optional().default(1),
    limit: z.coerce.number().int().min(1).max(100).optional().default(20),
    sortBy: z.string().optional().default('createdAt'),
    sortOrder: z.enum(['asc', 'desc']).optional().default('desc'),
});

export const GET = createApiHandler(
    async (_, { query }) => {
        const { q, role, skills, location, isActive, isVerified, page, limit, sortBy, sortOrder } = query;

        const filters = {
            role,
            skills,
            location,
            isActive,
            isVerified,
        };

        const pagination = {
            page,
            limit,
            sortBy,
            sortOrder,
        };

        const result = await userService.searchUsers(q || '', filters, pagination);

        return NextResponse.json(result);
    },
    {
        auth: {
            level: 'authenticated',
            permission: PERMISSIONS.USERS_READ
        },
        querySchema: searchQuerySchema,
        summary: 'Search users',
        description: 'Search and filter users with pagination',
        tags: ['Users', 'Search'],
    }
);