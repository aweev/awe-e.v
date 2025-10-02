// lib/services/auth/session-fingerprint.service.ts
import { prisma } from '@/lib/db';
import crypto from 'crypto';

export const sessionFingerprintService = {
    generateFingerprint(req: Request): string {
        const components = [
            req.headers.get('user-agent') || '',
            req.headers.get('accept-language') || '',
            // Don't include IP as it can change
        ];

        return crypto
            .createHash('sha256')
            .update(components.join('|'))
            .digest('hex');
    },

    async validateFingerprint(
        sessionId: string,
        currentFingerprint: string
    ): Promise<boolean> {
        const session = await prisma.userSession.findUnique({
            where: { id: sessionId },
            select: { fingerprint: true },
        });

        return session?.fingerprint === currentFingerprint;
    },
};