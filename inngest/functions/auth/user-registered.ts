import { inngest } from '@/inngest/client';
import { logger } from '@/lib/logger';
import { prisma } from '@/lib/db';

export const userRegistered = inngest.createFunction(
    {
        id: 'auth-user-registered',
        name: 'Handle User Registration',
    },
    { event: 'auth/user.registered' },
    async ({ event, step }) => {
        const { userId, locale } = event.data;
        const log = logger.child({ userId, locale });

        log.info('Processing user registration');

        // Get user details
        const user = await step.run('fetch-user', async () => {
            return await prisma.user.findUnique({
                where: { id: userId },
                select: {
                    id: true,
                    email: true,
                    username: true,
                    profile: {
                        select: {
                            firstName: true,
                            lastName: true,
                        },
                    },
                },
            });
        });

        if (!user) {
            throw new Error('User not found');
        }

        // Send welcome notification
        await step.run('send-welcome-notification', async () => {
            await inngest.send({
                name: 'notifications/send',
                data: {
                    type: 'USER_WELCOME',
                    payload: {
                        recipient: {
                            id: user.id,
                            email: user.email,
                            profile: null
                        },
                        userName: user.profile?.firstName || user.username || 'there',
                    },
                    options: {
                        locale,
                    },
                },
            });
        });

        // Create default notification preferences
        await step.run('create-notification-preferences', async () => {
            await prisma.userNotificationPreferences.create({
                data: {
                    userId,
                    channelPreferences: {
                        // Default: all notifications enabled on all channels
                        USER_WELCOME: {
                            in_app: true,
                            email: true,
                            push: false,
                            sms: false,
                        },
                    },
                },
            });
        });

        log.info('User registration processing completed');

        return { success: true };
    }
);
