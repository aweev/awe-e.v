// lib/services/audit.service.ts
import { NextRequest } from 'next/server';
import { posthog } from '@/lib/posthog';
import { prisma } from '@/lib/db';
import type { Prisma } from '@prisma/client';
import { logger } from '@/lib/logger';
import * as Sentry from '@sentry/nextjs';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import { InngestEvent } from '@/inngest/client';

const SENSITIVE_ACTIONS = new Set<string>([
    AUDIT_ACTIONS.LOGIN_FAILED,
    AUDIT_ACTIONS.PASSWORD_RESET_SUCCESS,
]);

function sanitizeMetadata(metadata?: Record<string, unknown> | null): Record<string, unknown> | null {
    if (!metadata) return null;
    const clone = { ...metadata };
    const sensitiveKeys = ['password', 'token', 'secret', 'authorization', 'code', 'oldPassword', 'newPassword'];
    for (const key of sensitiveKeys) {
        if (key in clone) clone[key] = '[REDACTED]';
    }
    return clone;
}

export interface AuditEvent {
    action: string;
    actorId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    requestId?: string;
    inngestRunId?: string;
    metadata?: Record<string, unknown> | null;
}

class AuditService {
    public async log(event: AuditEvent): Promise<void> {
        const sanitizedMetadata = sanitizeMetadata(event.metadata);
        logger.info({ ...event, metadata: sanitizedMetadata }, `[AUDIT] ${event.action}`);

        await this._logToDatabase(event, sanitizedMetadata);
        await this._logToAnalytics(event, sanitizedMetadata);
    }

    private async _logToDatabase(event: AuditEvent, sanitizedMetadata: Record<string, unknown> | null) {
        try {
            await prisma.auditLog.create({
                data: {
                    action: event.action,
                    actor: event.actorId ? { connect: { id: event.actorId } } : undefined,
                    meta: {
                        ip: event.ip,
                        userAgent: event.userAgent,
                        requestId: event.requestId,
                        inngestRunId: event.inngestRunId,
                        ...sanitizedMetadata,
                    } as Prisma.JsonObject,
                },
            });
        } catch (dbError) {
            logger.error({ err: dbError, event }, '[AUDIT-DB-ERROR] Failed to write audit log to database.');
            Sentry.captureException(dbError, { extra: { event, reason: 'Audit Log DB Write Failure' } });
        }
    }

    private async _logToAnalytics(event: AuditEvent, sanitizedMetadata: Record<string, unknown> | null) {
        if (posthog && !SENSITIVE_ACTIONS.has(event.action) && process.env.NODE_ENV === 'production') {
            try {
                posthog.capture({
                    distinctId: event.actorId || event.ip || 'anonymous',
                    event: event.action,
                    properties: { ...event, metadata: sanitizedMetadata, $ip: event.ip },
                });
            } catch (posthogError) {
                logger.error({ err: posthogError, event }, '[AUDIT-POSTHOG-ERROR] Failed to send audit log to PostHog.');
                Sentry.captureException(posthogError, { extra: { event, reason: 'Audit Log PostHog Write Failure' } });
            }
        }
    }

    public fromRequest(
        req: NextRequest,
        action: string,
        actorId?: string | null,
        metadata?: Record<string, unknown> | null,
    ): void {
        const ip =
            req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
            req.headers.get('x-real-ip') ||
            '127.0.0.1';
        const userAgent = req.headers.get('user-agent') || null;
        const requestId = req.headers.get('x-request-id') || crypto.randomUUID();

        this.log({ action, actorId, metadata, ip, userAgent, requestId });
    }

    public fromInngest(
        inngestEvent: InngestEvent,
        runId: string,
        action: string,
        actorId?: string | null,
        metadata?: Record<string, unknown> | null,
    ): void {
        this.log({
            action,
            actorId,
            metadata: { ...metadata, originalEventName: inngestEvent.name },
            inngestRunId: runId,
        });
    }
}

export const auditService = new AuditService();