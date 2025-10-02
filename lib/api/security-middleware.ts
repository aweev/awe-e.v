// lib/api/security-middleware.ts
import { NextRequest, NextResponse } from 'next/server';

export function addSecurityHeaders(response: NextResponse): NextResponse {
    // Security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '1; mode=block');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // CORS headers for API
    response.headers.set('Access-Control-Allow-Origin', process.env.NODE_ENV === 'production'
        ? 'https://awe-ev.org'
        : '*');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours

    return response;
}

export function handleOptions(request: NextRequest): NextResponse | null {
    if (request.method === 'OPTIONS') {
        const response = new NextResponse(null, { status: 200 });
        return addSecurityHeaders(response);
    }
    return null;
}