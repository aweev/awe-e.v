// lib/services/consent/consent.service.ts
import { prisma } from '@/lib/db';

export enum CookieCategory {
    STRICTLY_NECESSARY = 'strictly_necessary',
    ANALYTICS = 'analytics',
    MARKETING = 'marketing',
}

export interface ConsentPreferences {
    strictly_necessary: boolean; // Always true
    analytics: boolean;
    marketing: boolean;
    timestamp: Date;
}

export const consentService = {
    async recordConsent(
        userId: string | null,
        preferences: ConsentPreferences,
        ip?: string
    ): Promise<void> {
        if (userId) {
            await prisma.userConsent.upsert({
                where: { userId },
                create: {
                    userId,
                    preferences: preferences as any,
                    ipAddress: ip,
                },
                update: {
                    preferences: preferences as any,
                    updatedAt: new Date(),
                },
            });
        }
        // Also store in cookie for anonymous users
    },

    async getConsent(userId: string): Promise<ConsentPreferences | null> {
        const consent = await prisma.userConsent.findUnique({
            where: { userId },
        });
        return consent?.preferences as ConsentPreferences | null;
    },

    canUseAnalytics(consent: ConsentPreferences | null): boolean {
        return consent?.analytics ?? false;
    },
};