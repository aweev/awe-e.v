// lib/services/onboarding/onboarding-admin.service.ts
import { prisma } from "@/lib/db";
import { Role, Prisma } from "@prisma/client";
import { z } from "zod";
import { logger } from "@/lib/logger";
import * as crypto from "crypto";
import { inngest } from "@/inngest/client";

// Schemas
const createTemplateSchema = z.object({
    name: z.string().min(1).max(100),
    description: z.string().optional(),
    roles: z.array(z.nativeEnum(Role)),
    isDefault: z.boolean().optional(),
    steps: z.array(z.object({
        stepId: z.string(),
        rank: z.number(),
        isRequired: z.boolean(),
        roleWhitelist: z.array(z.nativeEnum(Role)).optional(),
        roleBlacklist: z.array(z.nativeEnum(Role)).optional(),
        showIf: z.record(z.any()).optional(),
        uiConfig: z.record(z.any()).optional(),
    })),
});

const createStepSchema = z.object({
    name: z.string().min(1).max(50).regex(/^[a-zA-Z0-9_]+$/),
    titleKey: z.string(),
    descKey: z.string(),
    component: z.string(),
    validationSchema: z.record(z.any()).optional(),
    defaultData: z.record(z.any()).optional(),
});

const updateConfigSchema = z.object({
    enabled: z.boolean().optional(),
    allowSkip: z.boolean().optional(),
    requireCompletionBeforeAccess: z.boolean().optional(),
    invitationExpiryDays: z.number().min(1).max(30).optional(),
    requireInvitationForAdmins: z.boolean().optional(),
    autoAssignTemplateByRole: z.boolean().optional(),
    sendWelcomeEmail: z.boolean().optional(),
    sendReminderEmails: z.boolean().optional(),
    reminderIntervalDays: z.number().min(1).max(30).optional(),
});

const inviteUserSchema = z.object({
    email: z.string().email(),
    roles: z.array(z.nativeEnum(Role)).min(1),
    organizationId: z.string().optional(),
    message: z.string().max(500).optional(),
});

export class OnboardingAdminService {
    // ============================================================================
    // TEMPLATE MANAGEMENT
    // ============================================================================

    async createTemplate(
        data: z.infer<typeof createTemplateSchema>,
        createdById: string
    ) {
        const validated = createTemplateSchema.parse(data);

        return prisma.$transaction(async (tx) => {
            // If this is set as default, unset other defaults
            if (validated.isDefault) {
                await tx.onboardingTemplate.updateMany({
                    where: { isDefault: true },
                    data: { isDefault: false },
                });
            }

            const template = await tx.onboardingTemplate.create({
                data: {
                    name: validated.name,
                    description: validated.description,
                    roles: validated.roles,
                    isDefault: validated.isDefault ?? false,
                    createdById,
                },
            });

            // Create paths
            for (const step of validated.steps) {
                await tx.onboardingPath.create({
                    data: {
                        templateId: template.id,
                        stepId: step.stepId,
                        rank: step.rank,
                        isRequired: step.isRequired,
                        roleWhitelist: step.roleWhitelist ?? [],
                        roleBlacklist: step.roleBlacklist ?? [],
                        showIf: step.showIf as Prisma.JsonValue,
                        uiConfig: step.uiConfig as Prisma.JsonValue,
                    },
                });
            }

            logger.info({ templateId: template.id, name: template.name },
                "Onboarding template created");

            return template;
        });
    }

    async updateTemplate(
        templateId: string,
        data: Partial<z.infer<typeof createTemplateSchema>>,
        updatedById: string
    ) {
        return prisma.$transaction(async (tx) => {
            if (data.isDefault) {
                await tx.onboardingTemplate.updateMany({
                    where: { id: { not: templateId }, isDefault: true },
                    data: { isDefault: false },
                });
            }

            const template = await tx.onboardingTemplate.update({
                where: { id: templateId },
                data: {
                    name: data.name,
                    description: data.description,
                    roles: data.roles,
                    isDefault: data.isDefault,
                    updatedById,
                },
            });

            // Update paths if provided
            if (data.steps) {
                // Delete existing paths
                await tx.onboardingPath.deleteMany({
                    where: { templateId },
                });

                // Create new paths
                for (const step of data.steps) {
                    await tx.onboardingPath.create({
                        data: {
                            templateId,
                            stepId: step.stepId,
                            rank: step.rank,
                            isRequired: step.isRequired,
                            roleWhitelist: step.roleWhitelist ?? [],
                            roleBlacklist: step.roleBlacklist ?? [],
                            showIf: step.showIf as Prisma.JsonValue,
                            uiConfig: step.uiConfig as Prisma.JsonValue,
                        },
                    });
                }
            }

            logger.info({ templateId, updatedById }, "Onboarding template updated");

            return template;
        });
    }

    async deleteTemplate(templateId: string) {
        const template = await prisma.onboardingTemplate.findUnique({
            where: { id: templateId },
        });

        if (!template) {
            throw new Error("Template not found");
        }

        if (template.isDefault) {
            throw new Error("Cannot delete default template");
        }

        await prisma.onboardingTemplate.delete({
            where: { id: templateId },
        });

        logger.info({ templateId }, "Onboarding template deleted");
    }

    async listTemplates(filters?: {
        isActive?: boolean;
        role?: Role;
    }) {
        return prisma.onboardingTemplate.findMany({
            where: {
                isActive: filters?.isActive,
                roles: filters?.role ? { has: filters.role } : undefined,
            },
            include: {
                path: {
                    include: { step: true },
                    orderBy: { rank: 'asc' },
                },
            },
            orderBy: [
                { isDefault: 'desc' },
                { name: 'asc' },
            ],
        });
    }

    async getTemplate(templateId: string) {
        return prisma.onboardingTemplate.findUnique({
            where: { id: templateId },
            include: {
                path: {
                    include: { step: true },
                    orderBy: { rank: 'asc' },
                },
            },
        });
    }

    // ============================================================================
    // STEP MANAGEMENT
    // ============================================================================

    async createStep(data: z.infer<typeof createStepSchema>) {
        const validated = createStepSchema.parse(data);

        const step = await prisma.onboardingStep.create({
            data: {
                name: validated.name,
                titleKey: validated.titleKey,
                descKey: validated.descKey,
                component: validated.component,
                validationSchema: validated.validationSchema as Prisma.JsonValue,
                defaultData: validated.defaultData as Prisma.JsonValue,
            },
        });

        logger.info({ stepId: step.id, name: step.name }, "Onboarding step created");

        return step;
    }

    async updateStep(
        stepId: string,
        data: Partial<z.infer<typeof createStepSchema>>
    ) {
        const step = await prisma.onboardingStep.update({
            where: { id: stepId },
            data: {
                titleKey: data.titleKey,
                descKey: data.descKey,
                component: data.component,
                validationSchema: data.validationSchema as Prisma.JsonValue,
                defaultData: data.defaultData as Prisma.JsonValue,
            },
        });

        logger.info({ stepId }, "Onboarding step updated");

        return step;
    }

    async deleteStep(stepId: string) {
        // Check if step is used in any template
        const usageCount = await prisma.onboardingPath.count({
            where: { stepId },
        });

        if (usageCount > 0) {
            throw new Error(
                `Cannot delete step. It is used in ${usageCount} template(s).`
            );
        }

        await prisma.onboardingStep.delete({
            where: { id: stepId },
        });

        logger.info({ stepId }, "Onboarding step deleted");
    }

    async listSteps(activeOnly = false) {
        return prisma.onboardingStep.findMany({
            where: activeOnly ? { isActive: true } : undefined,
            orderBy: { name: 'asc' },
        });
    }

    // ============================================================================
    // CONFIGURATION MANAGEMENT
    // ============================================================================

    async getConfig() {
        let config = await prisma.onboardingConfig.findUnique({
            where: { singleton: 'main' },
        });

        if (!config) {
            config = await prisma.onboardingConfig.create({
                data: { singleton: 'main' },
            });
        }

        return config;
    }

    async updateConfig(
        data: z.infer<typeof updateConfigSchema>,
        updatedBy: string
    ) {
        const validated = updateConfigSchema.parse(data);

        const config = await prisma.onboardingConfig.upsert({
            where: { singleton: 'main' },
            create: {
                singleton: 'main',
                ...validated,
                updatedBy,
            },
            update: {
                ...validated,
                updatedBy,
            },
        });

        logger.info({ updatedBy }, "Onboarding configuration updated");

        return config;
    }

    // ============================================================================
    // USER INVITATION SYSTEM
    // ============================================================================

    async inviteUser(
        data: z.infer<typeof inviteUserSchema>,
        invitedById: string
    ) {
        const validated = inviteUserSchema.parse(data);
        const config = await this.getConfig();

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { email: validated.email },
        });

        if (existingUser) {
            throw new Error("User with this email already exists");
        }

        // Check for existing pending invitation
        const existingInvitation = await prisma.userInvitation.findFirst({
            where: {
                email: validated.email,
                status: 'PENDING',
                expiresAt: { gte: new Date() },
            },
        });

        if (existingInvitation) {
            throw new Error("Active invitation already exists for this email");
        }

        // Generate secure token
        const token = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + config.invitationExpiryDays);

        const invitation = await prisma.userInvitation.create({
            data: {
                email: validated.email,
                token,
                roles: validated.roles,
                invitedById,
                organizationId: validated.organizationId,
                message: validated.message,
                expiresAt,
            },
        });

        // Send invitation email
        await inngest.send({
            name: 'admin/user.invited',
            data: {
                invitationId: invitation.id,
                email: validated.email,
                token,
                invitedById,
                roles: validated.roles,
                message: validated.message,
                locale: 'en',
            },
        });

        logger.info(
            { invitationId: invitation.id, email: validated.email, invitedById },
            "User invitation created"
        );

        return invitation;
    }

    async acceptInvitation(token: string, password: string) {
        const invitation = await prisma.userInvitation.findUnique({
            where: { token },
        });

        if (!invitation) {
            throw new Error("Invalid invitation token");
        }

        if (invitation.status !== 'PENDING') {
            throw new Error("Invitation has already been used or revoked");
        }

        if (invitation.expiresAt < new Date()) {
            await prisma.userInvitation.update({
                where: { id: invitation.id },
                data: { status: 'EXPIRED' },
            });
            throw new Error("Invitation has expired");
        }

        // Check if email is already registered
        const existingUser = await prisma.user.findUnique({
            where: { email: invitation.email },
        });

        if (existingUser) {
            throw new Error("User already exists");
        }

        // Create user
        const { passwordService } = await import("@/lib/services/auth/password.service");
        const hashedPassword = await passwordService.hash(password);

        const user = await prisma.$transaction(async (tx) => {
            const newUser = await tx.user.create({
                data: {
                    email: invitation.email,
                    hashedPassword,
                    roles: invitation.roles,
                    isVerified: true, // Invited users are pre-verified
                    emailVerified: new Date(),
                    invitationAcceptedFrom: invitation.id,
                    profile: {
                        create: {},
                    },
                    onboarding: {
                        create: {
                            steps: [] as any, // Will be populated by onboarding service
                        },
                    },
                },
            });

            // Mark invitation as accepted
            await tx.userInvitation.update({
                where: { id: invitation.id },
                data: {
                    status: 'ACCEPTED',
                    acceptedAt: new Date(),
                },
            });

            // If organization was specified, link user
            if (invitation.organizationId) {
                await tx.user.update({
                    where: { id: newUser.id },
                    data: { organizationId: invitation.organizationId },
                });
            }

            return newUser;
        });

        logger.info(
            { userId: user.id, invitationId: invitation.id },
            "User invitation accepted"
        );

        return user;
    }

    async revokeInvitation(invitationId: string, revokedBy: string) {
        const invitation = await prisma.userInvitation.update({
            where: { id: invitationId },
            data: { status: 'REVOKED' },
        });

        logger.info(
            { invitationId, revokedBy },
            "User invitation revoked"
        );

        return invitation;
    }

    async listInvitations(filters?: {
        status?: string;
        email?: string;
    }) {
        return prisma.userInvitation.findMany({
            where: {
                status: filters?.status as any,
                email: filters?.email,
            },
            include: {
                invitedBy: {
                    select: {
                        id: true,
                        email: true,
                        profile: {
                            select: {
                                firstName: true,
                                lastName: true,
                            },
                        },
                    },
                },
            },
            orderBy: { createdAt: 'desc' },
        });
    }

    // ============================================================================
    // USER ONBOARDING MANAGEMENT
    // ============================================================================

    async resetUserOnboarding(userId: string, adminId: string) {
        await prisma.userOnboarding.delete({
            where: { userId },
        });

        await prisma.user.update({
            where: { id: userId },
            data: {
                onboardingCompleted: false,
                onboardingStartedAt: null,
                onboardingCompletedAt: null,
                onboardingSkipped: false,
            },
        });

        logger.info({ userId, adminId }, "User onboarding reset by admin");
    }

    async forceCompleteOnboarding(userId: string, adminId: string) {
        await prisma.user.update({
            where: { id: userId },
            data: {
                onboardingCompleted: true,
                onboardingCompletedAt: new Date(),
            },
        });

        await prisma.userOnboarding.update({
            where: { userId },
            data: {
                isCompleted: true,
                completedAt: new Date(),
            },
        });

        logger.info({ userId, adminId }, "User onboarding force-completed by admin");
    }

    async getUserOnboardingStats() {
        const [
            total,
            completed,
            inProgress,
            notStarted,
            skipped,
        ] = await Promise.all([
            prisma.user.count(),
            prisma.user.count({ where: { onboardingCompleted: true } }),
            prisma.user.count({
                where: {
                    onboardingCompleted: false,
                    onboardingStartedAt: { not: null },
                },
            }),
            prisma.user.count({
                where: {
                    onboardingCompleted: false,
                    onboardingStartedAt: null,
                },
            }),
            prisma.user.count({ where: { onboardingSkipped: true } }),
        ]);

        return {
            total,
            completed,
            inProgress,
            notStarted,
            skipped,
            completionRate: total > 0 ? (completed / total) * 100 : 0,
        };
    }
}

export const onboardingAdminService = new OnboardingAdminService();