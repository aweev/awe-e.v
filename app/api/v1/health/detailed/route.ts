// app/api/v1/health/detailed/route.ts
import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';
import { pingRedis } from '@/lib/services/rate-limit/redis';

export async function GET() {
    const checks = {
        database: false,
        redis: false,
        timestamp: new Date().toISOString(),
    };

    try {
        await prisma.$queryRaw`SELECT 1`;
        checks.database = true;
    } catch (error) {
        console.error('Database health check failed:', error);
    }

    try {
        checks.redis = await pingRedis();
    } catch (error) {
        console.error('Redis health check failed:', error);
    }

    const isHealthy = checks.database && checks.redis;

    return NextResponse.json(
        {
            status: isHealthy ? 'healthy' : 'unhealthy',
            checks,
            version: process.env.npm_package_version || '1.0.0',
        },
        { status: isHealthy ? 200 : 503 }
    );
}