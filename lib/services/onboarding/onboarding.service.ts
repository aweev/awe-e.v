// lib/services/onboarding/onboarding.service.ts
import { z } from "zod";
import { prisma } from "@/lib/db";
import { Prisma, UserOnboarding, Role } from "@prisma/client";
import type { OnboardingProgress, OnboardingStep, OnboardingStepName } from "./onboarding.types";
import { buildProgress } from "./onboarding.progress";

import { ONBOARDING_STEPS_CONFIG } from './onboarding.steps.config';
import { ONBOARDING_PATHS, DEFAULT_ONBOARDING_PATH } from './onboarding.paths';

import { featureFlagService } from '@/lib/services/feature-flags/feature-flag.service';

const stepDataSchemas = {
  welcome: z.object({
    termsAccepted: z.boolean().refine(val => val === true, "Terms must be accepted")
  }),

  roleSelection: z.object({
    role: z.nativeEnum(Role)
  }),

  profile: z.object({
    firstName: z.string().min(1, "First name is required").max(50),
    lastName: z.string().min(1, "Last name is required").max(50),
    username: z.string().min(3).max(30).regex(/^[a-zA-Z0-9_.]+$/).optional().or(z.literal(''))
  }),

  volunteerDetails: z.object({
    skills: z.array(z.string()).min(1, "At least one skill is required"),
    bio: z.string().max(500).optional().or(z.literal(''))
  }),

  corporateDetails: z.object({
    organizationName: z.string().min(2, "Organization name is required").max(100),
    jobTitle: z.string().min(2, "Job title is required").max(100)
  }),

  institutionalDetails: z.object({
    institutionName: z.string().min(2, "Institution name is required").max(100),
    contactPersonTitle: z.string().min(2, "Contact title is required").max(100)
  }),

  preferences: z.object({
    newsletter: z.boolean()
  }),

  privacy: z.object({
    privacyAccepted: z.boolean().refine(val => val === true, "Privacy agreement required")
  }),

  finished: z.object({})
};

export class OnboardingError extends Error {
  constructor(
    message: string,
    public code: string,
    public step?: string,
    public cause?: Error
  ) {
    super(message);
    this.name = 'OnboardingError';
  }
}

export class ValidationError extends OnboardingError {
  constructor(message: string, step: string, public issues: z.ZodIssue[]) {
    super(message, 'VALIDATION_ERROR', step);
    this.name = 'ValidationError';
  }
}

export class StepNotFoundError extends OnboardingError {
  constructor(stepId: number, userId: string) {
    super(`Step ${stepId} not found for user ${userId}`, 'STEP_NOT_FOUND');
    this.name = 'StepNotFoundError';
  }
}

const prevStep = (steps: OnboardingStep[], currentIndex: number): number | null => {
  if (currentIndex <= 0) return null;
  return currentIndex - 1;
};

export const onboardingService = {
  validateStepData(stepName: OnboardingStepName, data: Record<string, unknown>): void {
    const schema = stepDataSchemas[stepName];
    if (!schema) {
      throw new OnboardingError(`No validation schema found for step: ${stepName}`, 'NO_SCHEMA', stepName);
    }

    const result = schema.safeParse(data);
    if (!result.success) {
      throw new ValidationError(
        `Validation failed for step ${stepName}`,
        stepName,
        result.error.issues
      );
    }
  },
  async generateStepsForRole_Dynamic(role: Role | null): Promise<OnboardingStep[]> {
    try {
      let templateName = 'DEFAULT';
      if (role) {
        const roleToTemplateMap: Partial<Record<Role, string>> = {
          ACTIVE_VOLUNTEER: 'VOLUNTEER',
          PROGRAM_MENTOR: 'VOLUNTEER',
          CORPORATE_PARTNER: 'CORPORATE',
          INSTITUTIONAL_PARTNER: 'INSTITUTIONAL',
        };
        templateName = roleToTemplateMap[role] || 'DEFAULT';
      }

      let template = await prisma.onboardingTemplate.findFirst({
        where: { name: templateName, isActive: true },
        include: {
          path: {
            include: { step: true },
            orderBy: { rank: 'asc' },
          },
        },
      });

      if (!template) {
        console.warn(`Template "${templateName}" not found, falling back to DEFAULT.`);
        template = await prisma.onboardingTemplate.findFirst({
          where: { name: 'DEFAULT', isActive: true },
          include: {
            path: {
              include: { step: true },
              orderBy: { rank: 'asc' },
            },
          },
        });
      }

      if (!template) {
        throw new OnboardingError(
          'No active default onboarding template found',
          'TEMPLATE_NOT_FOUND'
        );
      }

      return template.path.map((pathItem, index) => ({
        id: index,
        name: pathItem.step.name as OnboardingStepName,
        titleKey: pathItem.step.titleKey,
        descriptionKey: pathItem.step.descKey,
        component: pathItem.step.component,
        required: pathItem.isRequired,
        completed: false,
      }));
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        'Failed to generate dynamic steps',
        'DYNAMIC_GENERATION_FAILED',
        undefined,
        error as Error
      );
    }
  },

  generateStepsForRole_Static(role: Role | null): OnboardingStep[] {
    try {
      const path = role ? ONBOARDING_PATHS[role] : DEFAULT_ONBOARDING_PATH;

      const steps = path.map(stepName => {
        const stepConfig = ONBOARDING_STEPS_CONFIG.find(s => s.name === stepName);
        if (!stepConfig) {
          throw new OnboardingError(
            `Step config not found for: ${stepName}`,
            'STEP_CONFIG_NOT_FOUND',
            stepName
          );
        }
        return { ...stepConfig };
      });

      return steps.map((step, index) => ({
        ...step,
        id: index,
        completed: false,
      }));
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        'Failed to generate static steps',
        'STATIC_GENERATION_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async generateStepsForRole(userId: string, userRoles: Role[]): Promise<OnboardingStep[]> {
    try {
      const useDynamicSystem = await featureFlagService.isEnabled(
        'dynamic-onboarding',
        { userId, roles: userRoles }
      );

      const primaryRole = userRoles[0] || null;

      if (useDynamicSystem) {
        console.log(`[FF: ON] User ${userId} using DYNAMIC onboarding.`);
        return await this.generateStepsForRole_Dynamic(primaryRole);
      } else {
        console.log(`[FF: OFF] User ${userId} using STATIC onboarding.`);
        return this.generateStepsForRole_Static(primaryRole);
      }
    } catch (error) {
      console.error(`Failed to generate steps for user ${userId}:`, error);
      try {
        const primaryRole = userRoles[0] || null;
        console.log(`Falling back to static system for user ${userId}`);
        return this.generateStepsForRole_Static(primaryRole);
      } catch (fallbackError) {
        throw new OnboardingError(
          'Both dynamic and static step generation failed',
          'GENERATION_FAILED',
          undefined,
          fallbackError as Error
        );
      }
    }
  },

  async getOrCreate(userId: string): Promise<UserOnboarding> {
    try {
      const existing = await prisma.userOnboarding.findUnique({
        where: { userId }
      });

      if (existing) {
        const steps = existing.steps as unknown as OnboardingStep[];
        if (!Array.isArray(steps) || steps.length === 0) {
          console.warn(`Invalid steps data for user ${userId}, regenerating...`);
          const user = await prisma.user.findUnique({
            where: { id: userId },
            select: { roles: true },
          });

          const newSteps = await this.generateStepsForRole(userId, user?.roles ?? []);

          const updated = await prisma.userOnboarding.update({
            where: { userId },
            data: { steps: newSteps as unknown as Prisma.JsonArray },
          });

          return updated;
        }

        return existing;
      }

      const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { roles: true },
      });

      if (!user) {
        throw new OnboardingError(
          `User ${userId} not found`,
          'USER_NOT_FOUND'
        );
      }

      const roleSpecificSteps = await this.generateStepsForRole(userId, user.roles);

      return await prisma.userOnboarding.create({
        data: {
          userId,
          steps: roleSpecificSteps as unknown as Prisma.JsonArray,
        },
      });
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        `Failed to get or create onboarding for user ${userId}`,
        'GET_OR_CREATE_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async getProgress(userId: string): Promise<OnboardingProgress> {
    try {
      const record = await this.getOrCreate(userId);
      const steps = record.steps as unknown as OnboardingStep[];

      if (!Array.isArray(steps)) {
        throw new OnboardingError(
          'Invalid onboarding steps structure',
          'INVALID_STEPS_STRUCTURE'
        );
      }

      return buildProgress(steps);
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        `Failed to get progress for user ${userId}`,
        'GET_PROGRESS_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async completeStep(
    userId: string,
    stepId: number,
    data: Record<string, unknown>
  ): Promise<OnboardingProgress> {
    try {
      const record = await this.getOrCreate(userId);
      const currentSteps = record.steps as unknown as OnboardingStep[];

      const stepToComplete = currentSteps.find(step => step.id === stepId);
      if (!stepToComplete) {
        throw new StepNotFoundError(stepId, userId);
      }

      this.validateStepData(stepToComplete.name, data);

      let nextSteps: OnboardingStep[];

      if (stepToComplete.name === 'roleSelection' && data.role) {
        const newRole = data.role as Role;
        const newStepsForRole = await this.generateStepsForRole(userId, [newRole]);

        const roleSelectionIndex = newStepsForRole.findIndex(s => s.name === 'roleSelection');
        if (roleSelectionIndex !== -1) {
          newStepsForRole[roleSelectionIndex].completed = true;
          newStepsForRole[roleSelectionIndex].data = { role: newRole };
        }
        nextSteps = newStepsForRole;
      } else {
        nextSteps = currentSteps.map(step =>
          step.id === stepId ? { ...step, completed: true, data } : step
        );
      }

      await prisma.$transaction(async (tx) => {
        if (stepToComplete.name === 'corporateDetails' || stepToComplete.name === 'institutionalDetails') {
          const organizationName = (data.organizationName || data.institutionName) as string;
          if (organizationName) {
            const organization = await tx.organization.upsert({
              where: { name: organizationName },
              create: { name: organizationName },
              update: {}
            });
            await tx.user.update({
              where: { id: userId },
              data: { organizationId: organization.id }
            });
          }
        }

        if (stepToComplete.name === 'roleSelection' && data.role) {
          await tx.user.update({
            where: { id: userId },
            data: { roles: [data.role as Role] }
          });
        }

        const profileData = {
          firstName: typeof data.firstName === 'string' ? data.firstName : undefined,
          lastName: typeof data.lastName === 'string' ? data.lastName : undefined,
          organization: typeof data.organizationName === 'string' ? data.organizationName :
            typeof data.institutionName === 'string' ? data.institutionName : undefined,
          jobTitle: typeof data.jobTitle === 'string' ? data.jobTitle :
            typeof data.contactPersonTitle === 'string' ? data.contactPersonTitle : undefined,
          bio: typeof data.bio === 'string' ? data.bio : undefined,
        };

        const userData: Prisma.UserUpdateInput = {
          username: typeof data.username === 'string' ? data.username : undefined,
        };

        const preferencesData = {
          newsletterSubscription: typeof data.newsletter === 'boolean' ? data.newsletter : undefined,
        };

        if (Object.values(userData).some(v => v !== undefined)) {
          await tx.user.update({ where: { id: userId }, data: userData });
        }

        if (Object.values(profileData).some(v => v !== undefined)) {
          await tx.userProfile.upsert({
            where: { userId },
            create: { userId, ...profileData },
            update: profileData,
          });
        }

        if (Object.values(preferencesData).some(v => v !== undefined)) {
          await tx.userPreferences.upsert({
            where: { userId },
            create: { userId, ...preferencesData },
            update: preferencesData,
          });
        }

        if (stepToComplete.name === 'volunteerDetails' && Array.isArray(data.skills)) {
          const skillKeys = data.skills as string[];
          const userProfile = await tx.userProfile.findUnique({
            where: { userId },
            select: { id: true }
          });

          if (!userProfile) {
            throw new OnboardingError(
              'User profile not found for skill update',
              'PROFILE_NOT_FOUND',
              stepToComplete.name
            );
          }

          await tx.userSkill.deleteMany({ where: { userProfileId: userProfile.id } });

          if (skillKeys.length > 0) {
            const skillsInDb = await tx.skill.findMany({ where: { key: { in: skillKeys } } });
            if (skillsInDb.length !== skillKeys.length) {
              const foundKeys = new Set(skillsInDb.map(s => s.key));
              const missingKeys = skillKeys.filter(key => !foundKeys.has(key));
              throw new OnboardingError(
                `Skills not found: ${missingKeys.join(', ')}`,
                'SKILLS_NOT_FOUND',
                stepToComplete.name
              );
            }

            const userSkillsData = skillsInDb.map(skill => ({
              userProfileId: userProfile.id,
              skillId: skill.id
            }));
            await tx.userSkill.createMany({ data: userSkillsData });
          }
        }

        const progress = buildProgress(nextSteps);
        await tx.userOnboarding.update({
          where: { userId },
          data: {
            steps: nextSteps as unknown as Prisma.JsonArray,
            isCompleted: progress.isCompleted,
            completedAt: progress.isCompleted && !record.isCompleted ? new Date() : undefined,
          },
        });
      });

      return this.getProgress(userId);
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        `Failed to complete step ${stepId} for user ${userId}`,
        'COMPLETE_STEP_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async goBack(userId: string): Promise<OnboardingProgress> {
    try {
      const record = await this.getOrCreate(userId);
      const currentSteps = record.steps as unknown as OnboardingStep[];
      const progress = buildProgress(currentSteps);

      const previousStepIndex = prevStep(currentSteps, progress.currentStep);
      if (previousStepIndex === null) {
        return progress;
      }

      const stepToUndo = currentSteps[progress.currentStep];
      if (!stepToUndo) {
        throw new OnboardingError(
          'Current step not found',
          'CURRENT_STEP_NOT_FOUND'
        );
      }

      const nextSteps = currentSteps.map(step =>
        step.id === stepToUndo.id ? { ...step, completed: false } : step
      );

      await prisma.userOnboarding.update({
        where: { userId },
        data: {
          steps: nextSteps as unknown as Prisma.JsonArray,
          isCompleted: false,
        }
      });

      return this.getProgress(userId);
    } catch (error) {
      if (error instanceof OnboardingError) throw error;
      throw new OnboardingError(
        `Failed to go back for user ${userId}`,
        'GO_BACK_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async resetOnboarding(userId: string): Promise<void> {
    try {
      await prisma.userOnboarding.delete({
        where: { userId }
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2025') {
        return;
      }
      throw new OnboardingError(
        `Failed to reset onboarding for user ${userId}`,
        'RESET_FAILED',
        undefined,
        error as Error
      );
    }
  },

  async healthCheck(): Promise<{ status: 'ok' | 'error'; details: Record<string, any> }> {
    try {
      await prisma.$queryRaw`SELECT 1`;

      const templateCount = await prisma.onboardingTemplate.count();
      const activeTemplateCount = await prisma.onboardingTemplate.count({
        where: { isActive: true }
      });

      return {
        status: 'ok',
        details: {
          database: 'connected',
          templates: {
            total: templateCount,
            active: activeTemplateCount
          },
          timestamp: new Date().toISOString()
        }
      };
    } catch (error) {
      return {
        status: 'error',
        details: {
          error: error instanceof Error ? error.message : 'Unknown error',
          timestamp: new Date().toISOString()
        }
      };
    }
  }
};