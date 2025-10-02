// app/api/v1/auth/register/route.ts (Updated)

import { createApiHandler } from '@/lib/api-handler';
import { AccountExistsUnverifiedError, AccountExistsVerifiedError, PasswordPolicyError } from '@/lib/errors/auth.errors';
import type { Locale } from '@/lib/i18n';
import { getIpFromRequest, getLocaleFromRequest } from '@/lib/request';
import { signUpSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';

import { NextResponse } from 'next/server';

export const POST = createApiHandler(
    async (req, { body: credentials }) => {
        try {
            const ip = getIpFromRequest(req);
            const locale = getLocaleFromRequest(req) as Locale;

            await authService.register(credentials, ip, locale);

            return NextResponse.json({
                message: 'Registration successful. Please check your email.',
                requiresVerification: true,
            },
                { status: 201 }
            );
        } catch (error) {
            if (error instanceof AccountExistsUnverifiedError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'ACCOUNT_EXISTS_UNVERIFIED',
                    requiresVerification: true,
                },
                    { status: 200 }
                );
            }
            if (error instanceof AccountExistsVerifiedError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'ACCOUNT_EXISTS_VERIFIED',
                    requiresVerification: false,
                },
                    { status: 409 }
                );
            }
            if (error instanceof PasswordPolicyError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'PASSWORD_POLICY_VIOLATION',
                    issues: error.issues,
                },
                    { status: 400 }
                );
            }
            throw error;
        }
    },
    {
        limiter: 'auth',
        bodySchema: signUpSchema,
        summary: 'User registration',
        description: 'Registers a new user account',
        tags: ['Authentication'],
    }
);