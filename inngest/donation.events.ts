// inngest/donation.events.ts

import { inngest } from "./client";
import { prisma } from "@/lib/db";
import { emailService } from "@/lib/email/email.service";
import pdfService, { PDFService } from "@/lib/pdf/pdf.service";
import { ensureDate } from "@/lib/utils/date";
import { Decimal } from "@prisma/client/runtime/library";
import { getTranslations } from "@/lib/i18n";
import { storageService } from "@/lib/storage/cloudinary.service";

export const sendDonationReceipt = inngest.createFunction(
    {
        id: "send-donation-receipt-v2",
        name: "Generate, Upload, and Send PDF Receipt",
        retries: 3,
    },
    { event: "donation/completed.one_time" },
    async ({ event, step }) => {
        const { donationId, locale } = event.data;
        const t = getTranslations(locale); // Get translations oncename: "Generate, Upload, and Send PDF Receipt",

        // Re-fetch the donation to ensure we have correct data types (Date, Decimal)
        const donation = await step.run("fetch-donation-data", async () => {
            const result = await prisma.donation.findUnique({
                where: { id: donationId },
                include: { donor: { include: { profile: true } } },
            });
            if (!result) {
                // This is a permanent failure for this job
                throw new Error(`Donation with ID ${donationId} not found.`);
            }
            return result;
        });

        const donorProfile = donation.donor!.profile!;
        const donorEmail = donation.donor!.email!;

        const { formattedAmount, formattedDate } = await step.run("2-format-donation-data", async () => {
            const amount = new Decimal(donation.amount).toNumber();
            const date = ensureDate(donation.createdAt);
            return {
                formattedAmount: new Intl.NumberFormat(locale, { style: 'currency', currency: donation.currency }).format(amount),
                formattedDate: new Intl.DateTimeFormat(locale, { dateStyle: 'long' }).format(date),
            };
        });

        const pdfBufferJson = await step.run("3-generate-pdf-buffer", async () => {
            return await PDFService.generateReceiptPDF({
                donation: donation,
                formattedAmount,
                formattedDate,
                logoUrl: process.env.NEXT_PUBLIC_LOGO_URL!,
                messages: t.pdfReceipt
            });
        });

        const receiptUrl = await step.run("4-upload-pdf-to-storage", async () => {
            const pdfBuffer = Buffer.from(pdfBufferJson.data);
            const folder = `receipts/${new Date().getFullYear()}`;
            const publicId = `donation_${donation.id}`;
            return await storageService.uploadBuffer(pdfBuffer, folder, publicId);
        });


        await step.run("5-send-receipt-email", async () => {
            await emailService.sendDonationReceipt(
                donorEmail,
                donorProfile.firstName || 'Valued Supporter',
                formattedAmount,
                formattedDate,
                receiptUrl,
                locale
            );
        });

        return { status: "Success", message: `PDF receipt sent for donation ${donationId}.` };
    }
);