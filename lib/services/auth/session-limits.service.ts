import { prisma } from "@/lib/db";
import { auditService } from "../audit.service";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";

// lib/services/auth/session-limits.service.ts
export const sessionLimitsService = {
    async enforceLimit(userId: string, maxSessions: number = 5): Promise<void> {
        const sessions = await prisma.userSession.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
        });

        if (sessions.length >= maxSessions) {
            // Delete oldest sessions
            const toDelete = sessions.slice(maxSessions - 1);
            await prisma.userSession.deleteMany({
                where: {
                    id: { in: toDelete.map(s => s.id) },
                },
            });

            // Audit this
            await auditService.log({
                action: AUDIT_ACTIONS.SESSION_LIMIT_EXCEEDED,
                actorId: userId,
                metadata: { removedSessions: toDelete.length },
            });
        }
    },
};