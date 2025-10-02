// lib/shutdown.ts
import { getRedis } from './services/rate-limit/redis';
import { prisma } from './db';
import { logger } from './logger';

const signals = ['SIGTERM', 'SIGINT'] as const;

export function setupGracefulShutdown() {
    signals.forEach(signal => {
        process.on(signal, async () => {
            logger.info(`Received ${signal}, starting graceful shutdown...`);

            try {
                // Close Redis connection
                await getRedis().quit();
                logger.info('Redis connection closed');

                // Close Prisma connection
                await prisma.$disconnect();
                logger.info('Database connection closed');

                process.exit(0);
            } catch (error) {
                logger.error({ error }, 'Error during shutdown');
                process.exit(1);
            }
        });
    });
}