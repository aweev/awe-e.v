// lib/api/error-handler.ts 
import { NextResponse } from 'next/server';
import { ZodError } from 'zod';
import {
    AuthError,
    InvalidCredentialsError,
    AccountExistsError,
    InvalidTokenError,
    MfaRequiredError,
    PasswordPolicyError,
    AccountLockedError
} from '@/lib/errors/auth.errors';
import { logger } from '@/lib/logger';

export class ApiError extends Error {
    constructor(
        public statusCode: number,
        public message: string,
        public code?: string,
        public details?: unknown
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

export function handleApiError(error: unknown): NextResponse {
    // Log the error for debugging
    logger.error({ error }, 'API Error occurred');

    // Handle known error types
    if (error instanceof ZodError) {
        return NextResponse.json(
            {
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.flatten(),
            },
            { status: 400 }
        );
    }

    if (error instanceof InvalidTokenError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'INVALID_TOKEN',
            },
            { status: 401 }
        );
    }

    if (error instanceof InvalidCredentialsError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'INVALID_CREDENTIALS',
            },
            { status: 401 }
        );
    }

    if (error instanceof AccountLockedError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'ACCOUNT_LOCKED',
                lockedUntil: error.lockedUntil,
            },
            { status: 423 }
        );
    }

    if (error instanceof PasswordPolicyError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'PASSWORD_POLICY_VIOLATION',
                issues: error.issues,
            },
            { status: 400 }
        );
    }

    if (error instanceof AccountExistsError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'ACCOUNT_EXISTS',
            },
            { status: 409 }
        );
    }

    if (error instanceof MfaRequiredError) {
        return NextResponse.json(
            {
                message: error.message,
                mfaRequired: true,
                mfaToken: error.mfaToken,
            },
            { status: 200 }
        );
    }

    if (error instanceof AuthError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'AUTH_ERROR',
            },
            { status: 403 }
        );
    }

    if (error instanceof ApiError) {
        return NextResponse.json(
            {
                error: error.message,
                code: error.code,
                details: error.details,
            },
            { status: error.statusCode }
        );
    }

    // Handle unknown errors
    return NextResponse.json(
        {
            error: 'An unexpected error occurred',
            code: 'INTERNAL_ERROR',
        },
        { status: 500 }
    );
}

export interface ErrorPayload {
    error: string;
    code?: 'VALIDATION_ERROR' | 'INVALID_TOKEN' | 'INVALID_CREDENTIALS' | 'ACCOUNT_LOCKED' | 'PASSWORD_POLICY_VIOLATION' | 'ACCOUNT_EXISTS' | 'AUTH_ERROR' | 'INTERNAL_ERROR';
    details?: Record<string, unknown>
    lockedUntil?: string; // Will be an ISO date string
    issues?: string[]; // For password policy errors
}

export interface ApiErrorResponse {
    response?: {
        data?: ErrorPayload;
    };
}

export function isApiError(error: unknown): error is ApiErrorResponse {
    if (
        typeof error === 'object' &&
        error !== null &&
        'response' in error
    ) {
        const resp = (error as { response?: unknown }).response;
        if (
            typeof resp === 'object' &&
            resp !== null &&
            'data' in resp
        ) {
            return true;
        }
    }
    return false;
}
