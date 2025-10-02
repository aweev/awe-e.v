import { NonRetriableError } from 'inngest';
import { inngest } from "../client";
import { prisma } from "@/lib/db";
import { logger } from "@/lib/logger";
import { emailService } from "@/lib/email/email.service";
import { notificationRegistry, type AppNotificationType, type NotificationDefinition } from "@/lib/notifications/registry";
import type { NotificationType } from "@prisma/client";
import * as Sentry from "@sentry/nextjs";
import { renderTemplate } from "@/lib/notifications/template-renderer";
import { GenericNotificationEmail } from "@/lib/email/templates/GenericNotificationEmail";
import { z } from "zod";
import {
    NotificationChannelConfigSchema,
    NotificationTemplatesSchema,
} from "@/lib/notifications/schemas";
import type { Locale } from "@/lib/i18n";

interface RenderedContent {
    title: string;
    body: string;
    emailSubject: string;
    actionText: string;
    linkHref?: string;
}

interface BasePayload {
    recipient: {
        id: string;
        email: string;
    };
}

interface DispatchResult {
    channel: 'in_app' | 'email' | 'push' | 'sms';
    status: 'success' | 'failed';
    notificationId?: string;
    error?: string;
}


export const sendNotification = inngest.createFunction(
    {
        id: 'send-notification-v4',
        name: 'Send Dynamic Notification',
        retries: 3,
        concurrency: {
            limit: 100, // Process up to 100 notifications concurrently
        },
    },
    { event: 'notifications/send' },
    async ({ event, step, runId }) => {
        const { type, payload, options } = event.data;
        const locale = (options.locale || 'en') as Locale;
        const log = logger.child({
            inngestRunId: runId,
            notificationType: type,
            actorId: options.actorId
        });

        log.info('Processing notification event');

        // STEP 1: Fetch, Validate & Parse Configuration

        const { logic, parsedPayload, dbTemplate, channelConfig } = await step.run(
            'fetch-and-validate',
            async () => {
                const logic = notificationRegistry[type] as NotificationDefinition<any>;
                if (!logic) {
                    throw new NonRetriableError(
                        `Notification logic for type "${type}" not found in registry`
                    );
                }

                // Validate payload against schema
                const parsedPayload = logic.dataSchema.parse(payload);

                // Fetch template from database
                const rawDbTemplate = await prisma.notificationTemplate.findUnique({
                    where: { type: type as NotificationType }
                });

                if (!rawDbTemplate) {
                    throw new NonRetriableError(
                        `Notification template for type "${type}" not found in database`
                    );
                }

                try {
                    const parsedTemplates = NotificationTemplatesSchema.parse(
                        rawDbTemplate.templates
                    );
                    const parsedConfig = NotificationChannelConfigSchema.parse(
                        rawDbTemplate.defaultChannelConfig
                    );

                    return {
                        logic,
                        parsedPayload,
                        dbTemplate: parsedTemplates,
                        channelConfig: parsedConfig
                    };
                } catch (error) {
                    if (error instanceof z.ZodError) {
                        log.error(
                            { errors: error.issues },
                            'Template validation failed'
                        );
                        throw new NonRetriableError(
                            `Invalid template structure for type "${type}"`
                        );
                    }
                    throw error;
                }
            }
        );

        const recipient = (parsedPayload as BasePayload).recipient;
        log.info({ recipientId: recipient.id }, 'Payload validated');

        // STEP 2: Check User Preferences

        const userPreferences = await step.run(
            'check-user-preferences',
            async () => {
                const prefs = await prisma.userNotificationPreferences.findUnique({
                    where: { userId: recipient.id },
                });

                if (!prefs) {
                    // No preferences = use defaults (all enabled)
                    return channelConfig;
                }

                const channelPrefs = prefs.channelPreferences as Record<string, any>;
                const typePrefs = channelPrefs[type] as Record<string, boolean> | undefined;

                if (!typePrefs) {
                    // No type-specific preferences = use defaults
                    return channelConfig;
                }

                // Override channel config with user preferences
                return {
                    inApp: typePrefs.in_app !== false && channelConfig.inApp,
                    email: typePrefs.email !== false && channelConfig.email,
                    push: typePrefs.push !== false && (channelConfig as any).push,
                    sms: typePrefs.sms !== false && (channelConfig as any).sms,
                };
            }
        );

        log.info({ userPreferences }, 'User preferences applied');

        // STEP 3: Resolve Dynamic Data

        const resolvedData = await step.run(
            'resolve-dynamic-data',
            async () => {
                // Check if the dataResolver property exists (debug first)
                if (!('dataResolver' in logic) || typeof logic.dataResolver !== 'function') {
                    console.log('Available logic properties:', Object.keys(logic));
                    throw new NonRetriableError(`Data resolver not found for notification type "${type}". Available properties: ${Object.keys(logic).join(', ')}`);
                }
                try {
                    // Cast to any to handle the complex TypeScript union type issue
                    return await (logic as any).dataResolver(parsedPayload, locale);
                } catch (error) {
                    log.error({ err: error }, 'Data resolution failed');
                    Sentry.captureException(error, {
                        tags: { notificationType: type },
                        contexts: { payload: parsedPayload },
                    });
                    throw error;
                }
            }
        );

        // STEP 4: Render Content

        const content = await step.run('render-content', async () => {
            const templateForLocale = dbTemplate[locale] ?? dbTemplate['en'];

            if (!templateForLocale) {
                throw new NonRetriableError(
                    `No template found for locale "${locale}" or fallback "en"`
                );
            }

            // Find link in resolved data
            const linkKey = Object.keys(resolvedData).find(key =>
                key.endsWith('Link') || key.endsWith('Url')
            );
            const linkHref = linkKey ? String(resolvedData[linkKey]) : undefined;

            try {
                return {
                    title: renderTemplate(templateForLocale.title, resolvedData),
                    body: renderTemplate(templateForLocale.body, resolvedData),
                    emailSubject: renderTemplate(
                        templateForLocale.emailSubject,
                        resolvedData
                    ),
                    actionText: renderTemplate(
                        templateForLocale.actionText,
                        resolvedData
                    ),
                    linkHref,
                };
            } catch (error) {
                log.error({ err: error }, 'Template rendering failed');
                throw new NonRetriableError(
                    `Failed to render template for type "${type}"`
                );
            }
        });

        // STEP 5: Dispatch to Channels

        const dispatchResults = await step.run(
            'dispatch-to-channels',
            async () => {
                const dispatchPromises: Promise<DispatchResult>[] = [];

                if (userPreferences.inApp) {
                    dispatchPromises.push(
                        dispatchInApp(recipient.id, type, content, options.actorId)
                    );
                }

                if (userPreferences.email && recipient.email) {
                    dispatchPromises.push(
                        dispatchEmail(recipient.email, content)
                    );
                }

                // Add more channels as needed
                // if (userPreferences.push) { ... }
                // if (userPreferences.sms) { ... }

                const results = await Promise.allSettled(dispatchPromises);

                return results.map((result, index) => {
                    if (result.status === 'fulfilled') {
                        return result.value;
                    } else {
                        log.error(
                            { error: result.reason },
                            `Channel dispatch failed`
                        );
                        return {
                            channel: 'unknown' as any,
                            status: 'failed' as const,
                            error: result.reason?.message || 'Unknown error',
                        };
                    }
                });
            }
        );

        // STEP 6: Record Metrics & Audit

        await step.run('record-metrics', async () => {
            const successCount = dispatchResults.filter(
                r => r.status === 'success'
            ).length;
            const failureCount = dispatchResults.filter(
                r => r.status === 'failed'
            ).length;

            log.info(
                {
                    type,
                    recipientId: recipient.id,
                    successCount,
                    failureCount,
                    channels: dispatchResults.map(r => r.channel),
                },
                'Notification dispatch completed'
            );

            // Record in analytics/metrics system if available
            // await analyticsService.trackNotification({ ... });
        });
        return {
            status: 'completed',
            notificationType: type,
            recipientId: recipient.id,
            results: dispatchResults,
        };
    }
);

export const notificationDelivery = inngest.createFunction(
    {
        id: 'notification-delivery-v2',
        name: 'Notification Delivery Handler',
        retries: 3,
        concurrency: {
            limit: 200,
        },
    },
    { event: 'notification/deliver' },
    async ({ event, step, runId }) => {
        const { notificationId, channel, idempotencyKey } = event.data as {
            notificationId: string;
            channel: 'EMAIL' | 'IN_APP' | 'PUSH' | 'SMS';
            idempotencyKey: string;
        };

        const log = logger.child({
            inngestRunId: runId,
            notificationId,
            channel
        });

        // Check for duplicate delivery
        const existingDelivery = await step.run(
            'check-idempotency',
            async () => {
                return await prisma.notificationDelivery.findUnique({
                    where: { idempotencyKey },
                });
            }
        );

        if (existingDelivery && existingDelivery.status === 'SENT') {
            log.info('Duplicate delivery detected, skipping');
            return {
                success: true,
                reason: 'already-delivered',
                deliveryId: existingDelivery.id,
            };
        }

        // Execute delivery
        const result = await step.run('execute-delivery', async () => {
            try {
                const notification = await prisma.notification.findUnique({
                    where: { id: notificationId },
                    include: {
                        recipient: {
                            select: {
                                id: true,
                                email: true,
                                profile: {
                                    select: {
                                        firstName: true,
                                        lastName: true,
                                    },
                                },
                            },
                        },
                    },
                });

                if (!notification) {
                    throw new NonRetriableError('Notification not found');
                }

                // Execute channel-specific delivery logic
                let deliveryResult: { success: boolean; details?: any };

                switch (channel) {
                    case 'EMAIL':
                        deliveryResult = await executeEmailDelivery(notification);
                        break;
                    case 'IN_APP':
                        deliveryResult = { success: true }; // Already created
                        break;
                    case 'PUSH':
                        deliveryResult = await executePushDelivery(notification);
                        break;
                    case 'SMS':
                        deliveryResult = await executeSmsDelivery(notification);
                        break;
                    default:
                        throw new NonRetriableError(`Unknown channel: ${channel}`);
                }

                // Update delivery record
                await prisma.notificationDelivery.update({
                    where: { idempotencyKey },
                    data: {
                        status: deliveryResult.success ? 'SENT' : 'FAILED',
                        executedAt: new Date(),
                        failReason: deliveryResult.success
                            ? null
                            : 'Delivery execution failed',
                    },
                });

                return deliveryResult;
            } catch (error) {
                log.error({ err: error }, 'Delivery execution failed');

                // Update delivery record with failure
                await prisma.notificationDelivery.update({
                    where: { idempotencyKey },
                    data: {
                        status: 'FAILED',
                        executedAt: new Date(),
                        failReason: error instanceof Error
                            ? error.message
                            : 'Unknown error',
                        retryCount: {
                            increment: 1,
                        },
                    },
                });

                throw error;
            }
        });

        log.info({ result }, 'Delivery completed');

        return {
            success: true,
            deliveryResult: result,
        };
    }
);


async function dispatchInApp(
    recipientId: string,
    type: AppNotificationType,
    content: RenderedContent,
    actorId?: string
): Promise<DispatchResult> {
    try {
        const notification = await prisma.notification.create({
            data: {
                recipientId,
                actorId: actorId || null,
                type: type as NotificationType,
                title: content.title,
                body: content.body,
                linkHref: content.linkHref || null,
                isRead: false,
            },
        });

        logger.info(
            { notificationId: notification.id, recipientId },
            'In-app notification created'
        );

        return {
            channel: 'in_app',
            status: 'success',
            notificationId: notification.id,
        };
    } catch (error) {
        logger.error(
            { err: error, recipientId, type },
            'Failed to dispatch in-app notification'
        );
        Sentry.captureException(error, {
            tags: { channel: 'in_app', notificationType: type },
        });
        throw error;
    }
}

async function dispatchEmail(
    to: string,
    content: RenderedContent
): Promise<DispatchResult> {
    try {
        const component = GenericNotificationEmail({
            body: content.body,
            actionText: content.actionText,
            actionUrl: content.linkHref,
        });

        await emailService.sendGenericEmail(to, content.emailSubject, component);

        logger.info({ to, subject: content.emailSubject }, 'Email sent');

        return {
            channel: 'email',
            status: 'success',
        };
    } catch (error) {
        logger.error(
            { err: error, to, subject: content.emailSubject },
            'Failed to dispatch email'
        );
        Sentry.captureException(error, {
            tags: { channel: 'email' },
        });
        throw error;
    }
}

async function executeEmailDelivery(notification: any): Promise<{ success: boolean }> {
    // Email delivery logic
    return { success: true };
}

async function executePushDelivery(notification: any): Promise<{ success: boolean }> {
    // Push notification delivery logic
    return { success: true };
}

async function executeSmsDelivery(notification: any): Promise<{ success: boolean }> {
    // SMS delivery logic
    return { success: true };
}
