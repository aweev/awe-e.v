// lib/services/auth/password-policy.service.ts
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';

export interface PasswordPolicyConfig {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    preventCommonPasswords: boolean;
    preventUserInfo: boolean;
    maxAgeDays?: number;
    preventReuse: number; // Number of previous passwords to check
}

const DEFAULT_CONFIG: PasswordPolicyConfig = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventCommonPasswords: true,
    preventUserInfo: true,
    maxAgeDays: 90,
    preventReuse: 5,
};

// List of common passwords to prevent
const COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'password123',
    'admin', 'letmein', 'welcome', 'monkey', '1234567890'
];

export class PasswordPolicyError extends Error {
    constructor(
        public issues: string[],
        message = 'Password does not meet security requirements'
    ) {
        super(message);
        this.name = 'PasswordPolicyError';
    }
}

export const passwordPolicyService = {
    async getConfig(): Promise<PasswordPolicyConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    async validatePassword(
        password: string,
        userInfo?: { email?: string; firstName?: string; lastName?: string; username?: string }
    ): Promise<{ isValid: boolean; issues?: string[] }> {
        const config = await this.getConfig();
        const issues: string[] = [];

        // Check minimum length
        if (password.length < config.minLength) {
            issues.push(`Password must be at least ${config.minLength} characters long`);
        }

        // Check for uppercase letters
        if (config.requireUppercase && !/[A-Z]/.test(password)) {
            issues.push('Password must contain at least one uppercase letter');
        }

        // Check for lowercase letters
        if (config.requireLowercase && !/[a-z]/.test(password)) {
            issues.push('Password must contain at least one lowercase letter');
        }

        // Check for numbers
        if (config.requireNumbers && !/\d/.test(password)) {
            issues.push('Password must contain at least one number');
        }

        // Check for special characters
        if (config.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            issues.push('Password must contain at least one special character');
        }

        // Check against common passwords
        if (config.preventCommonPasswords) {
            const lowerPassword = password.toLowerCase();
            if (COMMON_PASSWORDS.some(common => lowerPassword.includes(common))) {
                issues.push('Password cannot contain common words or patterns');
            }
        }

        // Check for user information
        if (config.preventUserInfo && userInfo) {
            const lowerPassword = password.toLowerCase();
            const { email, firstName, lastName, username } = userInfo;

            if (email && lowerPassword.includes(email.split('@')[0].toLowerCase())) {
                issues.push('Password cannot contain parts of your email address');
            }

            if (firstName && lowerPassword.includes(firstName.toLowerCase())) {
                issues.push('Password cannot contain your first name');
            }

            if (lastName && lowerPassword.includes(lastName.toLowerCase())) {
                issues.push('Password cannot contain your last name');
            }

            if (username && lowerPassword.includes(username.toLowerCase())) {
                issues.push('Password cannot contain your username');
            }
        }

        return {
            isValid: issues.length === 0,
            issues: issues.length > 0 ? issues : undefined
        };
    },

    async checkPasswordHistory(userId: string, newPassword: string): Promise<{ isReuse: boolean; issues?: string[] }> {
        const config = await this.getConfig();

        if (config.preventReuse <= 0) {
            return { isReuse: false };
        }

        // Get user's password history
        const passwordHistory = await prisma.passwordHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: config.preventReuse
        });

        // Check if new password matches any previous passwords
        for (const entry of passwordHistory) {
            const isMatch = await bcrypt.compare(newPassword, entry.hashedPassword);
            if (isMatch) {
                return {
                    isReuse: true,
                    issues: [`You cannot reuse a password from your last ${config.preventReuse} passwords`]
                };
            }
        }

        return { isReuse: false };
    },

    async savePasswordToHistory(userId: string, hashedPassword: string): Promise<void> {
        // Add new password to history
        await prisma.passwordHistory.create({
            data: {
                userId,
                hashedPassword
            }
        });

        // Clean up old password history entries (keep only the last N)
        const config = await this.getConfig();
        if (config.preventReuse > 0) {
            const historyEntries = await prisma.passwordHistory.findMany({
                where: { userId },
                orderBy: { createdAt: 'desc' }
            });

            if (historyEntries.length > config.preventReuse) {
                const entriesToDelete = historyEntries.slice(config.preventReuse);
                const idsToDelete = entriesToDelete.map(entry => entry.id);

                await prisma.passwordHistory.deleteMany({
                    where: {
                        id: { in: idsToDelete }
                    }
                });
            }
        }
    }
};