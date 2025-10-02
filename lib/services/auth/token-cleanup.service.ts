import { prisma } from "@/lib/db";
import { logger } from "@/lib/logger";

// lib/services/auth/token-cleanup.service.ts
export const tokenCleanupService = {
    async cleanupExpiredTokens(): Promise<number> {
        const result = await prisma.token.deleteMany({
            where: {
                expiresAt: { lt: new Date() },
                used: false,
            },
        });

        logger.info(
            { count: result.count },
            '[TOKEN_CLEANUP] Removed expired tokens'
        );

        return result.count;
    },
};

// Run this as a cron job or scheduled task