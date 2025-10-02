// lib/api-handler.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAccessToken } from '@/lib/services/auth/jwt.service';
import type { AccessTokenPayload } from '@/types/auth.types';
import { consumeLogin, consumeGlobal } from '@/lib/services/rate-limit';
import { getIpFromRequest } from '@/lib/request';
import { auditService } from '@/lib/services/audit.service';
import {
    AuthError,
    InvalidTokenError,
} from '@/lib/errors/auth.errors';
import { ADMIN_ROLES } from '@/lib/helpers/roles';
import type { Role } from '@prisma/client';
import { hasPermission } from '@/lib/utils/permissions.utils';
import { type PermissionString } from '@/lib/audit/actions';
import * as Sentry from '@sentry/nextjs';
import { logger } from '@/lib/logger';
import { addSecurityHeaders, handleOptions } from '@/lib/api/security-middleware';
import { handleApiError } from '@/lib/api/error-handler';

type LimiterType = 'global' | 'auth' | 'passwordReset' | 'strict' | 'none';

type AuthOptions =
    | { level: 'public' }
    | {
        level: 'authenticated';
        allowedRoles?: readonly Role[];
        permission?: PermissionString;
    }
    | {
        level: 'admin';
        allowedRoles?: readonly Role[];
        permission?: PermissionString;
    };

interface HandlerOptions<TBody, TQuery> {
    auth?: AuthOptions;
    limiter?: LimiterType;
    bodySchema?: z.ZodSchema<TBody>;
    querySchema?: z.ZodSchema<TQuery>;
    description?: string;
    summary?: string;
    tags?: string[];
}

type ApiHandlerContext<
    TBody,
    TQuery,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
> = {
    params: TParams;
    session: AccessTokenPayload;
    body: TBody;
    query: TQuery;
};

type ApiHandler<
    TBody = unknown,
    TQuery = unknown,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
> = (
    req: NextRequest,
    context: ApiHandlerContext<TBody, TQuery, TParams>
) => Promise<NextResponse>;

async function getSessionFromRequest(req: NextRequest): Promise<AccessTokenPayload | null> {
    const authHeader = req.headers.get("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return null;
    }

    try {
        const token = authHeader.substring(7);
        return await verifyAccessToken(token);
    } catch {
        return null;
    }
}

export function createApiHandler<
    TBody = unknown,
    TQuery = unknown,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
>(
    handler: ApiHandler<TBody, TQuery, TParams>,
    options: HandlerOptions<TBody, TQuery> = {}
) {
    const {
        auth = { level: "public" },
        limiter: limiterType = "global",
        bodySchema,
        querySchema,
    } = options;

    return async (req: NextRequest, context: { params: TParams }) => {
        // Handle OPTIONS requests for CORS
        const optionsResponse = handleOptions(req);
        if (optionsResponse) return optionsResponse;

        let session: AccessTokenPayload | null = null;
        const requestId = req.headers.get('x-request-id') || crypto.randomUUID();

        // Create response headers
        const responseHeaders = new Headers();
        responseHeaders.set('x-request-id', requestId);

        try {
            const ip = getIpFromRequest(req);

            // Rate limiting using your implementation
            if (limiterType !== "none" && ip) {
                let rateLimitResult;

                if (limiterType === "auth") {
                    rateLimitResult = await consumeLogin(ip);
                } else {
                    rateLimitResult = await consumeGlobal(ip);
                }

                if (!rateLimitResult.allowed) {
                    auditService.fromRequest(req, "api:rate_limit_exceeded" as PermissionString, null, {
                        limiter: limiterType,
                        ip,
                    });

                    const response = NextResponse.json({
                        error: "Too many requests.",
                        code: 'RATE_LIMIT_EXCEEDED',
                        retryAfter: rateLimitResult.retryAfterSeconds
                    }, { status: 429 });

                    response.headers.set('Retry-After', rateLimitResult.retryAfterSeconds.toString());
                    return addSecurityHeaders(response);
                }
            }

            session = await getSessionFromRequest(req);

            // Authentication checks
            if (auth.level === "authenticated" || auth.level === "admin") {
                if (!session) {
                    throw new InvalidTokenError("Authentication required. Please log in.");
                }

                if (auth.level === "admin" && !ADMIN_ROLES.some((role) => session!.roles.includes(role))) {
                    throw new AuthError("Forbidden: Administrator access is required for this resource.");
                }

                if (
                    auth.allowedRoles?.length &&
                    !auth.allowedRoles.some((role) => session!.roles.includes(role))
                ) {
                    throw new AuthError(
                        `Forbidden: Requires one of the following roles: ${auth.allowedRoles.join(", ")}`
                    );
                }

                if (auth.permission) {
                    const userPermissions = new Set<PermissionString>(
                        (session.permissions as PermissionString[]) || []
                    );
                    if (!hasPermission(userPermissions, auth.permission)) {
                        throw new AuthError(
                            `Forbidden: You do not have the required permission ('${auth.permission}') for this action.`
                        );
                    }
                }
            }

            // Parse query parameters
            let query: TQuery = {} as TQuery;
            if (querySchema) {
                const searchParams = Object.fromEntries(req.nextUrl.searchParams);
                query = await querySchema.parseAsync(searchParams);
            }

            // Parse request body
            let body: TBody = {} as TBody;
            if (req.method !== "GET" && req.method !== "DELETE" && bodySchema) {
                const reqJson = await req.json();
                body = await bodySchema.parseAsync(reqJson);
            }

            // Execute the handler
            const result = await handler(req, { ...context, session: session!, body, query });

            // Add security headers to response
            if (result instanceof Response) {
                return addSecurityHeaders(result);
            }

            return result;

        } catch (error: unknown) {
            const actorId = session?.sub;

            // Log the error
            logger.error({
                error: error instanceof Error ? error.message : String(error),
                stack: error instanceof Error ? error.stack : undefined,
                requestId,
                url: req.url,
                method: req.method,
                actorId
            }, '[API ERROR] Exception in API handler');

            // Send to Sentry in production
            if (process.env.NODE_ENV === 'production') {
                Sentry.captureException(error, {
                    extra: {
                        requestId,
                        url: req.url,
                        method: req.method,
                        actorId
                    },
                    tags: {
                        module: "ApiHandler",
                        endpoint: req.url
                    }
                });
            }

            // Handle specific error types
            return handleApiError(error);
        }
    };
}