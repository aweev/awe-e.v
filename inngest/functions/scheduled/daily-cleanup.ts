import { inngest } from '@/inngest/client';
import { notificationService } from '@/lib/services/notification/notification.service';
import { logger } from '@/lib/logger';
import { prisma } from '@/lib/db';

export const dailyCleanup = inngest.createFunction(
    {
        id: 'daily-cleanup',
        name: 'Daily Cleanup Job',
    },
    { cron: '0 2 * * *' }, // Run at 2 AM daily
    async ({ step }) => {
        const log = logger.child({ job: 'daily-cleanup' });

        log.info('Starting daily cleanup job');

        // Clean up old read notifications (90 days)
        const deletedCount = await step.run('cleanup-old-notifications', async () => {
            return await notificationService.cleanupOldNotifications(90);
        });

        // Clean up failed deliveries (30 days)
        const cleanedDeliveries = await step.run('cleanup-failed-deliveries', async () => {
            const cutoffDate = new Date();
            cutoffDate.setDate(cutoffDate.getDate() - 30);

            const result = await prisma.notificationDelivery.deleteMany({
                where: {
                    status: 'FAILED',
                    createdAt: {
                        lt: cutoffDate,
                    },
                    retryCount: {
                        gte: 3, // Only delete after max retries
                    },
                },
            });

            return result.count;
        });

        log.info(
            {
                deletedNotifications: deletedCount,
                cleanedDeliveries,
            },
            'Daily cleanup completed'
        );

        return {
            success: true,
            deletedNotifications: deletedCount,
            cleanedDeliveries,
        };
    }
);