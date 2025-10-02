// inngest/auth.events.ts

import { inngest } from "./client";
import { prisma } from "@/lib/db";
import { emailService } from "@/lib/email/email.service";
import { passwordService } from "@/lib/auth/password/password.service";
import { logger } from "@/lib/logger";
import { auditService } from "@/lib/services/audit.service";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";
import * as Sentry from "@sentry/nextjs";

// --- User Registered / Verification Email Event ---
export const sendVerificationEmail = inngest.createFunction(
    {
        id: "send-verification-email-v3",
        name: "Send User Verification Email",
        // Idempotency ensures this function only runs successfully once per user registration.
        // The key is based on the user ID from the event payload.
        idempotency: "event.data.userId",
        retries: 3,
    },
    { event: "auth/user.registered" },
    async ({ event, step, runId }) => {
        const { userId, locale } = event.data;
        const log = logger.child({ inngestRunId: runId, userId });

        log.info("Starting verification email process.");

        const user = await step.run("1-fetch-user-data", async () => {
            return await prisma.user.findUnique({
                where: { id: userId },
                include: { profile: true },
            });
        });

        if (!user || user.isVerified) {
            log.warn("Skipping verification: User not found or already verified.");
            return { status: "Skipped", reason: "User not found or already verified." };
        }

        const rawToken = await step.run("2-create-verification-token", async () => {
            // This reuses your existing logic for token creation, now wrapped in a step.
            return await passwordService.createVerificationToken(user.id);
        });

        await step.run("3-send-verification-email", async () => {
            try {
                await emailService.sendVerificationEmail(
                    user.email,
                    user.profile?.firstName || 'User',
                    rawToken,
                    locale
                );
            } catch (error) {
                log.error({ err: error }, "Failed to send verification email via provider.");
                Sentry.captureException(error, {
                    extra: { userId, locale, runId },
                    tags: { module: "Inngest", function: "sendVerificationEmail" },
                });
                // Re-throwing the error tells Inngest to retry this step
                throw error;
            }
        });

        log.info("Verification email sent successfully.");

        auditService.fromInngest(event, runId, AUDIT_ACTIONS.USER_REGISTERED, userId);

        return { status: "Success", message: `Verification email sent to ${user.email}` };
    }
);

// --- Password Reset Requested Event ---
export const sendPasswordResetEmail = inngest.createFunction(
    {
        id: "send-password-reset-email-v3",
        name: "Send Password Reset Email",
        // A user might accidentally request a reset multiple times.
        // Idempotency prevents sending multiple emails for the same initial request.
        idempotency: "event.data.userId",
        retries: 3,
    },
    { event: "auth/password.reset_requested" },
    async ({ event, step, runId }) => {
        const { userId, locale } = event.data;
        const log = logger.child({ inngestRunId: runId, userId });

        log.info("Starting password reset email process.");

        const user = await step.run("1-fetch-user-data", async () => {
            return await prisma.user.findUnique({
                where: { id: userId },
                include: { profile: true },
            });
        });

        if (!user) {
            log.warn("Skipping password reset: User not found.");
            // We don't throw an error because this isn't a retryable state.
            return { status: "Skipped", reason: "User not found." };
        }

        const rawToken = await step.run("2-create-password-reset-token", async () => {
            return await passwordService.createPasswordResetToken(user.id);
        });

        await step.run("3-send-password-reset-email", async () => {
            try {
                await emailService.sendPasswordResetEmail(
                    user.email,
                    user.profile?.firstName || 'User',
                    rawToken,
                    locale
                );
            } catch (error) {
                log.error({ err: error }, "Failed to send password reset email via provider.");
                Sentry.captureException(error, {
                    extra: { userId, locale, runId },
                    tags: { module: "Inngest", function: "sendPasswordResetEmail" },
                });
                throw error;
            }
        });

        log.info("Password reset email sent successfully.");

        auditService.fromInngest(event, runId, AUDIT_ACTIONS.PASSWORD_RESET_REQUESTED, userId);

        return { status: "Success", message: `Password reset email sent to ${user.email}` };
    }
);