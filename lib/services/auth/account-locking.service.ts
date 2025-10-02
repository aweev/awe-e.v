// lib/services/auth/account-locking.service.ts
import { prisma } from '@/lib/db';
import { add, sub } from 'date-fns';
import { auditService } from '@/lib/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';

export interface AccountLockingConfig {
    maxAttempts: number;
    lockoutDurationMinutes: number;
    resetAfterMinutes?: number;
}

const DEFAULT_CONFIG: AccountLockingConfig = {
    maxAttempts: 5,
    lockoutDurationMinutes: 15,
    resetAfterMinutes: 60,
};

export class AccountLockedError extends Error {
    constructor(
        public lockedUntil: Date,
        message = 'Account has been temporarily locked due to too many failed login attempts. Please try again later.'
    ) {
        super(message);
        this.name = 'AccountLockedError';
    }
}

export const accountLockingService = {
    async getConfig(): Promise<AccountLockingConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    async recordFailedAttempt(email: string): Promise<{ isLocked: boolean; lockedUntil?: Date }> {
        const config = await this.getConfig();
        const now = new Date();

        // Cutoff = attempts considered only within the resetAfterMinutes window
        const cutoffTime = sub(now, { minutes: config.resetAfterMinutes || 60 });

        // Record new failed attempt
        await prisma.failedLoginAttempt.create({
            data: { email }
        });

        // Count recent attempts (within cutoff)
        const attemptsCount = await prisma.failedLoginAttempt.count({
            where: {
                email,
                createdAt: { gte: cutoffTime }
            }
        });

        // Check if account should be locked
        if (attemptsCount >= config.maxAttempts) {
            const lockedUntil = add(now, { minutes: config.lockoutDurationMinutes });

            // Update user lock info
            await prisma.user.updateMany({
                where: { email },
                data: { lockedUntil }
            });

            await auditService.log({
                action: AUDIT_ACTIONS.ACCOUNT_LOCKED,
                metadata: { email, attemptsCount, lockedUntil }
            });

            return { isLocked: true, lockedUntil };
        }

        return { isLocked: false };
    },

    async resetFailedAttempts(email: string): Promise<void> {
        await prisma.failedLoginAttempt.deleteMany({ where: { email } });
        await prisma.user.updateMany({
            where: { email },
            data: { lockedUntil: null }
        });
    },

    async isAccountLocked(email: string): Promise<{ isLocked: boolean; lockedUntil?: Date }> {
        const user = await prisma.user.findUnique({
            where: { email },
            select: { lockedUntil: true }
        });

        if (!user) return { isLocked: false };

        const now = new Date();
        if (user.lockedUntil && user.lockedUntil > now) {
            return { isLocked: true, lockedUntil: user.lockedUntil };
        }

        // If lock has expired, reset lock info
        if (user.lockedUntil && user.lockedUntil <= now) {
            await this.resetFailedAttempts(email);
        }

        return { isLocked: false };
    }
};
