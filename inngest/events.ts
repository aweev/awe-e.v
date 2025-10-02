// inngest/events.ts

import type { Locale } from '@/lib/i18n';
import { AppNotificationType, NotificationPayload } from '@/lib/notifications/registry';
import type { Channel, Role } from '@prisma/client';

/**
 * ==================================================================
 * AWE e.V. Inngest Event Registry
 * ==================================================================
 * This file is the single source of truth for all events sent to Inngest.
 * By defining events and their payloads here, we gain full type-safety
 * across our application when sending or receiving background jobs.
 *
 * @see https://www.inngest.com/docs/ts/events/send
 * ==================================================================
 */

type NotificationEvents = {
    [K in AppNotificationType]: {
        name: 'notifications/send';
        data: {
            type: K;
            payload: NotificationPayload<K>;
            options: {
                actorId?: string;
                locale?: string;
            };
        };
    };
};

type NotificationEventUnion = NotificationEvents[AppNotificationType];

export type InngestEvents = {
    // AUTH EVENTS
    'auth/user.registered': {
        name: 'auth/user.registered';
        data: {
            userId: string;
            locale: Locale;
        };
    };

    'auth/password.reset_requested': {
        name: 'auth/password.reset_requested';
        data: {
            userId: string;
            locale: Locale;
        };
    };

    'auth/email.verification_requested': {
        name: 'auth/email.verification_requested';
        data: {
            userId: string;
            locale: Locale;
        };
    };

    // ADMIN EVENTS 
    'admin/user.created': {
        name: 'admin/user.created';
        data: {
            userId: string;
            inviterId: string;
            assignedRoles: Role[];
            locale: Locale;
        };
    };

    // DONATION EVENTS
    'donation/completed.one_time': {
        name: 'donation/completed.one_time';
        data: {
            donationId: string;
            donorId?: string;
            locale: Locale;
        };
    };

    'donation/recurring.created': {
        name: 'donation/recurring.created';
        data: {
            donationId: string;
            donorId: string;
            locale: Locale;
        };
    };

    // EVENT MANAGEMENT EVENTS
    'event/registration.succeeded': {
        name: 'event/registration.succeeded';
        data: {
            registrationId: string;
            userId: string;
            eventId: string;
            locale: Locale;
        };
    };

    'event/registration.waitlisted': {
        name: 'event/registration.waitlisted';
        data: {
            registrationId: string;
            userId: string;
            eventId: string;
            locale: Locale;
        };
    };

    'event/promoted.from_waitlist': {
        name: 'event/promoted.from_waitlist';
        data: {
            registrationId: string;
            userId: string;
            eventId: string;
            locale: Locale;
        };
    };

    'event/reminder.upcoming': {
        name: 'event/reminder.upcoming';
        data: {
            eventId: string;
            userIds: string[];
            locale: Locale;
        };
    };

    // PROGRAM EVENTS
    'program/application.submitted': {
        name: 'program/application.submitted';
        data: {
            enrolmentId: string;
            userId: string;
            programId: string;
            locale: Locale;
        };
    };

    'program/application.approved': {
        name: 'program/application.approved';
        data: {
            enrolmentId: string;
            userId: string;
            programId: string;
            locale: Locale;
        };
    };

    'program/application.rejected': {
        name: 'program/application.rejected';
        data: {
            enrolmentId: string;
            userId: string;
            programId: string;
            locale: Locale;
        };
    };

    // VOLUNTEER EVENTS
    'volunteer/application.submitted': {
        name: 'volunteer/application.submitted';
        data: {
            applicationId: string;
            userId: string;
            locale: Locale;
        };
    };

    'volunteer/opportunity.new': {
        name: 'volunteer/opportunity.new';
        data: {
            opportunityId: string;
            targetRoles?: Role[];
            locale: Locale;
        };
    };

    // COMMUNITY EVENTS
    'community/story.submitted': {
        name: 'community/story.submitted';
        data: {
            storyId: string;
            authorId: string;
            locale: Locale;
        };
    };

    'community/story.published': {
        name: 'community/story.published';
        data: {
            storyId: string;
            authorId: string;
            locale: Locale;
        };
    };

    // NOTIFICATION EVENTS
    'notifications/send': NotificationEventUnion;

    'notification/deliver': {
        name: 'notification/deliver';
        data: {
            notificationId: string;
            channel: Channel;
            idempotencyKey: string;
        };
    };

    // SCHEDULED/MAINTENANCE EVENTS
    'scheduled/daily.cleanup': {
        name: 'scheduled/daily.cleanup';
        data: {
            timestamp: number;
        };
    };

    'scheduled/weekly.digest': {
        name: 'scheduled/weekly.digest';
        data: {
            timestamp: number;
        };
    };
};

export type AuthUserRegisteredEvent = InngestEvents['auth/user.registered'];
export type AdminUserCreatedEvent = InngestEvents['admin/user.created'];
export type DonationCompletedEvent = InngestEvents['donation/completed.one_time'];
export type EventRegistrationSucceededEvent = InngestEvents['event/registration.succeeded'];
export type CommunityStorySubmittedEvent = InngestEvents['community/story.submitted'];
