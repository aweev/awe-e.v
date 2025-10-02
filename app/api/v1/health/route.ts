// app/api/v1/health/route.ts
import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';

export async function GET() {
    try {
        await prisma.$queryRaw`SELECT 1`;
        return NextResponse.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
        });
    } catch  {
        return NextResponse.json(
            {
                status: 'unhealthy',
                error: 'Database connection failed',
            },
            { status: 503 }
        );
    }
}

// // app/api/health/route.ts
// import { NextRequest, NextResponse } from 'next/server';
// import { prisma } from '@/lib/db';
// import { performanceService } from '@/lib/monitoring/performance.service';
// import { errorTrackingService } from '@/lib/monitoring/error-tracking.service';

// export async function GET(request: NextRequest) {
//   try {
//     // Check database connection
//     await prisma.$queryRaw`SELECT 1;
    
//     // Check database performance
//     const dbPerformance = await prisma.$queryRaw`SELECT
//       SELECT
//         COUNT(*) as total_users,
//         COUNT(DISTINCT email) as active_users
//       FROM users
//     `;

//     // Check Redis connection
//     const redisHealth = await checkRedisHealth();
    
//     // Check performance metrics
//     const metrics = performanceService.getMetrics();
    
//     const healthStatus = {
//       status: 'healthy',
//       timestamp: new Date().toISOString(),
//       services: {
//         database: dbPerformance.total_users > 0,
//         redis: redisHealth.status === 'up',
//         performance: metrics.fcp < 2500, // Good FCP score
//         lcp: metrics.lcp < 4000, // Good LCP score
//         cls: metrics.cls < 0.1, // Good CLS score
//         fid: metrics.fid < 100, // Good FID score
//         tti: metrics.tti < 100, // Good TTI score
//       },
//       version: process.env.npm_package_version,
//       environment: process.env.NODE_ENV,
//       uptime: '99.9%',
//     };

//     return NextResponse.json(healthStatus, {
//       status: healthStatus.status === 'healthy' ? 200 : 503,
//       ...healthStatus,
//     });
//   } catch (error) {
//     await errorTrackingService.logError(error, {
//       context: {
//         route: request.url,
//         userAgent: request.headers.get('user-agent'),
//       },
//     });

//     return NextResponse.json(
//       { status: 'unhealthy' },
//       { status: 503 }
//     );
//   }
// }