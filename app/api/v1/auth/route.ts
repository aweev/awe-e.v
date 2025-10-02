// app/api/v1/auth/route.ts
import { NextResponse } from 'next/server';

export async function GET() {
    return NextResponse.json({
        message: 'AWE e.V. Authentication API v1',
        version: '1.0.0',
        endpoints: {
            login: '/api/v1/auth/login',
            logout: '/api/v1/auth/logout',
            register: '/api/v1/auth/register',
            refresh: '/api/v1/auth/refresh',
            'verify-email': '/api/v1/auth/verify-email',
            'password-reset': '/api/v1/auth/password-reset',
            mfa: {
                verify: '/api/v1/auth/mfa/verify',
            },
            oauth: {
                google: '/api/v1/auth/oauth/google',
                facebook: '/api/v1/auth/oauth/facebook',
            },
        },
        documentation: '/api/v1/docs',
    });
}