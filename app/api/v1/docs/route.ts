// app/api/v1/docs/route.ts
import { NextResponse } from 'next/server';
import { apiDocs } from '@/lib/api/docs-generator';

export async function GET() {
    const openApiSpec = apiDocs.generateOpenApiSpec();

    return NextResponse.json(openApiSpec, {
        headers: {
            'Content-Type': 'application/json',
        },
    });
}