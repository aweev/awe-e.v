// inngest/community.events.ts 

import { inngest } from "./client";
import { prisma } from "@/lib/db";
import { emailService } from "@/lib/email/email.service";
import { logger } from "@/lib/logger";
import * as Sentry from "@sentry/nextjs";

export const sendStoryConfirmation = inngest.createFunction(
    {
        id: "send-story-submission-confirmation-v2", // Version up
        name: "Send Story Submission Confirmation Email",
        retries: 3, // Add retries for resilience
    },
    { event: "community/story.submitted" },
    async ({ event, step }) => {
        const { storyId, authorId, locale } = event.data;

        // Step 1: Fetch the author's data (retryable)
        const author = await step.run("fetch-story-author-data", async () => {
            const result = await prisma.user.findUnique({
                where: { id: authorId },
                include: { profile: true },
            });
            if (!result || !result.profile) {
                // This is a permanent failure for this job, so we don't re-throw.
                // We log it and let the function exit gracefully.
                logger.error({ authorId, storyId }, "Author or profile not found for story submission. Cannot send confirmation.");
                Sentry.captureMessage(`Author not found for story submission: authorId=${authorId}`, 'error');
                return null;
            }
            return result;
        });

        // If the author couldn't be found, stop the function.
        if (!author) {
            return { status: "Failed", reason: `Author with ID ${authorId} not found.` };
        }

        // Step 2: Send the confirmation email (retryable)
        await step.run("send-confirmation-email", async () => {
            await emailService.sendStorySubmissionConfirmation(
                author.email,
                author.profile?.firstName || 'Community Member',
                locale
            );
        });

        logger.info({ storyId, authorId }, "Story submission confirmation email sent successfully.");

        return { status: "Success", message: `Confirmation sent for story ${storyId}.` };
    }
);