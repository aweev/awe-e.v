// inngest/admin.events.ts

import { inngest } from "./client";
import { prisma } from "@/lib/db";
import { emailService } from "@/lib/email/email.service";
import { passwordService } from "@/lib/auth/password/password.service";
import { logger } from "@/lib/logger";
import { auditService } from "@/lib/services/audit.service";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";
import * as Sentry from "@sentry/nextjs";
import { AdminUserCreatedEvent } from "./events";
import { InngestEvent } from "@/inngest/client";

export const sendAdminWelcomeEmail = inngest.createFunction(
    {
        id: "send-admin-welcome-email-v2",
        name: "Send Admin Welcome & Password Setup Email",
        idempotency: "event.data.userId",
        retries: 3,
    },
    { event: "admin/user.created" },
    async ({ event, step, runId }) => {
        // ✅ Now TypeScript knows event.data has assignedRoles
        const { userId, locale, inviterId, assignedRoles } = event.data;

        const log = logger.child({ inngestRunId: runId, userId, inviterId });
        log.info("Starting admin welcome email process.");

        // 1️⃣ Fetch user & profile
        const user = await step.run("1-fetch-admin-user-data", async () => {
            const result = await prisma.user.findUnique({
                where: { id: userId },
                include: { profile: true },
            });
            if (!result || !result.profile) {
                log.error("Cannot send welcome email: User or profile not found.");
                Sentry.captureMessage(
                    `Admin welcome failed: User or profile not found for ID: ${userId}`,
                    "error"
                );
                return null;
            }
            return result;
        });

        if (!user) {
            return { status: "Failed", reason: `User with ID ${userId} not found.` };
        }

        // 2️⃣ Create password setup token
        const rawToken = await step.run("2-create-password-setup-token", async () => {
            return await passwordService.createPasswordResetToken(user.id);
        });

        // 3️⃣ Send welcome email
        await step.run("3-send-admin-welcome-email", async () => {
            try {
                await emailService.sendAdminWelcomeEmail(
                    user.email,
                    user.profile?.firstName || "New Admin",
                    rawToken,
                    locale
                );
            } catch (error) {
                log.error({ err: error }, "Failed to send admin welcome email via provider.");
                Sentry.captureException(error, {
                    extra: { userId, locale, runId },
                    tags: { module: "Inngest", function: "sendAdminWelcomeEmail" },
                });
                throw error;
            }
        });

        log.info("Admin welcome email sent successfully.");

        // 4️⃣ Audit
        auditService.fromInngest(
            event,
            runId,
            AUDIT_ACTIONS.ADMIN_USER_CREATED,
            inviterId,
            {
                createdUserId: userId,
                assignedRoles,
            }
        );

        return { status: "Success", message: `Admin welcome email sent to ${user.email}` };
    }
);

// Export the type for use in other files
export type { AdminUserCreatedEvent };