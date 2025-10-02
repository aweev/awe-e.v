// app/api/v1/docs/markdown/route.ts
import { NextResponse } from 'next/server';
import { apiDocs } from '@/lib/api/docs-generator';

export async function GET() {
    const markdown = apiDocs.generateMarkdown();

    return new NextResponse(markdown, {
        headers: {
            'Content-Type': 'text/markdown',
        },
    });
}