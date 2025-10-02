// lib/services/auth/password-expiry.service.ts
import { add, differenceInDays } from 'date-fns';
import { passwordPolicyService } from './password-policy.service';
import { prisma } from '@/lib/db';

export const passwordExpiryService = {
    async checkPasswordExpiry(userId: string): Promise<{
        isExpired: boolean;
        daysUntilExpiry?: number;
        shouldWarn: boolean;
    }> {
        const config = await passwordPolicyService.getConfig();

        if (!config.maxAgeDays) {
            return { isExpired: false, shouldWarn: false };
        }

        const latestPassword = await prisma.passwordHistory.findFirst({
            where: { userId },
            orderBy: { createdAt: 'desc' },
        });

        if (!latestPassword) {
            return { isExpired: false, shouldWarn: false };
        }

        const expiryDate = add(latestPassword.createdAt, { days: config.maxAgeDays });
        const daysUntilExpiry = differenceInDays(expiryDate, new Date());

        return {
            isExpired: daysUntilExpiry <= 0,
            daysUntilExpiry: Math.max(0, daysUntilExpiry),
            shouldWarn: daysUntilExpiry <= 14 && daysUntilExpiry > 0,
        };
    },
};