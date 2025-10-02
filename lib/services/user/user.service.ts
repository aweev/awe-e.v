// lib/services/user/user.service.ts
import { prisma } from '@/lib/db';
import { User, UserProfile, UserPreferences, UserSkill, Role } from '@prisma/client';
import { auditService } from '@/lib/services/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import { logger } from '@/lib/logger';
import { z } from 'zod';
import { cache } from 'react';
import {
    AppError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    ValidationError
} from '@/lib/errors/errors';
import { sanitizeUserData, buildUserWhereClause } from '@/lib/utils/user.utils';
import {
    PaginationParams,
    SkillData,
    skillSchema,
    UpdatePreferencesData,
    updatePreferencesSchema,
    UpdateProfileData,
    updateProfileSchema,
    UserDeviceDto,
    UserExportData,
    UserSearchFilters,
    UserStats,
    BulkUserOperation,
    UserActivitySummary,
    ProfileCompletionStatus
} from '@/types/user.types';
import { LRUCache } from 'lru-cache';
import * as Sentry from '@sentry/nextjs';

// ============================================================================
// CACHING LAYER
// ============================================================================

const userCache = new LRUCache<string, any>({
    max: 500,
    ttl: 1000 * 60 * 5, // 5 minutes
});

const CACHE_KEYS = {
    user: (id: string) => `user:${id}`,
    userSkills: (id: string) => `user:${id}:skills`,
    userDevices: (id: string) => `user:${id}:devices`,
    userStats: (id: string) => `user:${id}:stats`,
    profileCompletion: (id: string) => `user:${id}:completion`,
};

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

async function validateUserExists(userId: string): Promise<User> {
    const user = await prisma.user.findUnique({
        where: { id: userId },
        select: { id: true, isActive: true, email: true }
    });

    if (!user) {
        throw new NotFoundError('User');
    }

    return user as User;
}

async function validateUserActive(userId: string): Promise<void> {
    const user = await validateUserExists(userId);

    if (!user.isActive) {
        throw new ForbiddenError('User account is deactivated');
    }
}

function invalidateUserCache(userId: string): void {
    userCache.delete(CACHE_KEYS.user(userId));
    userCache.delete(CACHE_KEYS.userSkills(userId));
    userCache.delete(CACHE_KEYS.userDevices(userId));
    userCache.delete(CACHE_KEYS.userStats(userId));
    userCache.delete(CACHE_KEYS.profileCompletion(userId));
}

// ============================================================================
// USER SERVICE
// ============================================================================

export const userService = {
    getUserById: cache(async (userId: string, includeRelations = true) => {
        try {
            const cacheKey = CACHE_KEYS.user(userId);
            const cached = userCache.get(cacheKey);

            if (cached) {
                return cached;
            }

            const user = await prisma.user.findUnique({
                where: { id: userId },
                include: includeRelations ? {
                    profile: true,
                    preferences: true,
                    onboarding: true,
                } : undefined,
            });

            if (!user) {
                throw new NotFoundError('User');
            }

            const sanitized = sanitizeUserData(user);
            userCache.set(cacheKey, sanitized);

            return sanitized;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch user by ID');
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'UserService', operation: 'getUserById' },
                extra: { userId }
            });

            throw new InternalServerError('Could not fetch user.');
        }
    }),

    async getUsersByIds(userIds: string[]): Promise<any[]> {
        try {
            if (userIds.length === 0) return [];

            const cachedUsers = userIds
                .map(id => ({ id, user: userCache.get(CACHE_KEYS.user(id)) }))
                .filter(({ user }) => user !== undefined);

            const uncachedIds = userIds.filter(
                id => !cachedUsers.some(cached => cached.id === id)
            );

            if (uncachedIds.length === 0) {
                return cachedUsers.map(({ user }) => user);
            }

            const users = await prisma.user.findMany({
                where: { id: { in: uncachedIds } },
                include: { profile: true, preferences: true },
            });

            users.forEach(user => {
                const sanitized = sanitizeUserData(user);
                userCache.set(CACHE_KEYS.user(user.id), sanitized);
            });

            return [
                ...cachedUsers.map(({ user }) => user),
                ...users.map(sanitizeUserData)
            ];
        } catch (error) {
            logger.error({ err: error, userIds }, '[USER_SERVICE] Failed to fetch users by IDs');
            throw new InternalServerError('Could not fetch users.');
        }
    },

    async getUserByEmail(email: string): Promise<any> {
        try {
            const user = await prisma.user.findUnique({
                where: { email: email.toLowerCase().trim() },
                include: { profile: true, preferences: true },
            });

            if (!user) {
                throw new NotFoundError('User');
            }

            return sanitizeUserData(user);
        } catch (error) {
            logger.error({ err: error, email }, '[USER_SERVICE] Failed to fetch user by email');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not fetch user.');
        }
    },

    // PROFILE MANAGEMENT

    async updateProfile(
        userId: string,
        data: UpdateProfileData,
        actorId: string
    ): Promise<UserProfile> {
        try {
            const validatedData = updateProfileSchema.parse(data);

            await validateUserActive(userId);

            if (validatedData.phone) {
                const existingPhone = await prisma.userProfile.findFirst({
                    where: {
                        phone: validatedData.phone,
                        userId: { not: userId }
                    }
                });

                if (existingPhone) {
                    throw new ValidationError('Phone number already in use', [
                        { path: ['phone'], message: 'This phone number is already registered' }
                    ]);
                }
            }

            const updatedProfile = await prisma.userProfile.upsert({
                where: { userId },
                update: {
                    ...validatedData,
                    updatedAt: new Date(),
                },
                create: {
                    userId,
                    ...validatedData
                },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_PROFILE_UPDATED,
                actorId: actorId,
                metadata: {
                    targetUserId: userId,
                    updatedFields: Object.keys(validatedData),
                    changes: validatedData
                },
            });

            logger.info(
                { userId, actorId, fields: Object.keys(validatedData) },
                '[USER_SERVICE] Profile updated successfully'
            );

            return updatedProfile;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to update user profile');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid profile data', error.issues);
            }
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'UserService', operation: 'updateProfile' },
                extra: { userId, data }
            });

            throw new InternalServerError('Could not update profile.');
        }
    },

    async getProfileCompletion(userId: string): Promise<ProfileCompletionStatus> {
        try {
            const cacheKey = CACHE_KEYS.profileCompletion(userId);
            const cached = userCache.get(cacheKey);

            if (cached) return cached;

            const user = await prisma.user.findUnique({
                where: { id: userId },
                include: { profile: true, onboarding: true },
            });

            if (!user) throw new NotFoundError('User');

            const requiredFields = {
                email: !!user.email,
                emailVerified: !!user.emailVerified,
                firstName: !!user.profile?.firstName,
                lastName: !!user.profile?.lastName,
                phone: !!user.profile?.phone,
                bio: !!user.profile?.bio,
                avatarUrl: !!user.profile?.avatarUrl || !!user.avatar,
                city: !!user.profile?.city,
                country: !!user.profile?.country,
                onboardingCompleted: !!user.onboarding?.isCompleted,
            };

            const optionalFields = {
                birthDate: !!user.profile?.birthDate,
                jobTitle: !!user.profile?.jobTitle,
                company: !!user.profile?.company,
                linkedin: !!user.profile?.linkedin,
                twitter: !!user.profile?.twitter,
                interests: (user.profile?.interests as string[])?.length > 0,
            };

            const totalRequired = Object.keys(requiredFields).length;
            const completedRequired = Object.values(requiredFields).filter(Boolean).length;
            const requiredPercentage = (completedRequired / totalRequired) * 70; // 70% weight

            const totalOptional = Object.keys(optionalFields).length;
            const completedOptional = Object.values(optionalFields).filter(Boolean).length;
            const optionalPercentage = (completedOptional / totalOptional) * 30; // 30% weight

            const completion = {
                percentage: Math.round(requiredPercentage + optionalPercentage),
                requiredFields: {
                    total: totalRequired,
                    completed: completedRequired,
                    missing: Object.entries(requiredFields)
                        .filter(([_, completed]) => !completed)
                        .map(([field]) => field),
                },
                optionalFields: {
                    total: totalOptional,
                    completed: completedOptional,
                    missing: Object.entries(optionalFields)
                        .filter(([_, completed]) => !completed)
                        .map(([field]) => field),
                },
                isComplete: completedRequired === totalRequired,
            };

            userCache.set(cacheKey, completion);
            return completion;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to calculate profile completion');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not calculate profile completion.');
        }
    },

    // PREFERENCES MANAGEMENT

    async updatePreferences(
        userId: string,
        data: UpdatePreferencesData,
        actorId: string
    ): Promise<UserPreferences> {
        try {
            const validatedData = updatePreferencesSchema.parse(data);

            const updatedPreferences = await prisma.userPreferences.upsert({
                where: { userId },
                update: {
                    ...validatedData,
                    updatedAt: new Date(),
                },
                create: {
                    userId,
                    ...validatedData
                },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_PREFERENCES_UPDATED,
                actorId,
                metadata: {
                    targetUserId: userId,
                    updatedFields: Object.keys(validatedData)
                },
            });

            logger.info(
                { userId, actorId, fields: Object.keys(validatedData) },
                '[USER_SERVICE] Preferences updated successfully'
            );

            return updatedPreferences;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to update user preferences');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid preferences data', error.issues);
            }

            throw new InternalServerError('Could not update preferences.');
        }
    },

    async getPreferences(userId: string): Promise<UserPreferences> {
        try {
            let preferences = await prisma.userPreferences.findUnique({
                where: { userId },
            });

            if (!preferences) {
                preferences = await prisma.userPreferences.create({
                    data: {
                        userId,
                    },
                });
            }

            return preferences;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch user preferences');
            throw new InternalServerError('Could not fetch preferences.');
        }
    },

    // AVATAR MANAGEMENT

    async updateAvatar(
        userId: string,
        avatarUrl: string,
        actorId: string
    ): Promise<Omit<User, 'hashedPassword' | 'mfaSecret'>> {
        try {
            z.string().url('Invalid URL format.').parse(avatarUrl);

            await validateUserActive(userId);

            const [updatedUser] = await prisma.$transaction([
                prisma.user.update({
                    where: { id: userId },
                    data: { avatar: avatarUrl },
                }),
                prisma.userProfile.upsert({
                    where: { userId },
                    update: { avatarUrl },
                    create: { userId, avatarUrl },
                }),
            ]);

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_AVATAR_UPDATED,
                actorId,
                metadata: { targetUserId: userId, avatarUrl },
            });

            logger.info({ userId, actorId }, '[USER_SERVICE] Avatar updated successfully');

            return sanitizeUserData(updatedUser);
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to update user avatar');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid avatar URL.', error.issues);
            }

            throw new InternalServerError('Could not update avatar.');
        }
    },

    async deleteAvatar(userId: string, actorId: string): Promise<void> {
        try {
            await validateUserActive(userId);

            await prisma.$transaction([
                prisma.user.update({
                    where: { id: userId },
                    data: { avatar: null },
                }),
                prisma.userProfile.update({
                    where: { userId },
                    data: { avatarUrl: null },
                }),
            ]);

            invalidateUserCache(userId);

            await auditService.log({
                action: 'user:avatar_deleted',
                actorId,
                metadata: { targetUserId: userId },
            });

            logger.info({ userId, actorId }, '[USER_SERVICE] Avatar deleted successfully');
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to delete user avatar');
            throw new InternalServerError('Could not delete avatar.');
        }
    },

    // SKILLS MANAGEMENT

    getUserSkills: cache(async (userId: string) => {
        try {
            const cacheKey = CACHE_KEYS.userSkills(userId);
            const cached = userCache.get(cacheKey);

            if (cached) return cached;

            const userSkills = await prisma.userSkill.findMany({
                where: { profile: { userId } },
                include: { skill: true },
                orderBy: [
                    { skill: { category: 'asc' } },
                    { skill: { name: 'asc' } }
                ],
            });

            userCache.set(cacheKey, userSkills);
            return userSkills;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch user skills');
            throw new InternalServerError('Could not fetch user skills.');
        }
    }),

    async addOrUpdateSkill(
        userId: string,
        skillData: SkillData,
        actorId: string
    ): Promise<UserSkill> {
        try {
            const { skillId, level } = skillSchema.parse(skillData);

            await validateUserActive(userId);

            const [skill, userProfile] = await Promise.all([
                prisma.skill.findUnique({ where: { id: skillId } }),
                prisma.userProfile.upsert({
                    where: { userId },
                    update: {},
                    create: { userId },
                }),
            ]);

            if (!skill) throw new NotFoundError('Skill');

            const updatedSkill = await prisma.userSkill.upsert({
                where: {
                    userProfileId_skillId: {
                        userProfileId: userProfile.id,
                        skillId
                    }
                },
                update: { level },
                create: { userProfileId: userProfile.id, skillId, level },
            });

            userCache.delete(CACHE_KEYS.userSkills(userId));
            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_SKILL_UPDATED,
                actorId,
                metadata: { targetUserId: userId, skillId, level },
            });

            logger.info(
                { userId, actorId, skillId, level },
                '[USER_SERVICE] Skill added/updated successfully'
            );

            return updatedSkill;
        } catch (error) {
            logger.error({ err: error, userId, skillData }, '[USER_SERVICE] Failed to add/update user skill');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid skill data', error.issues);
            }
            if (error instanceof AppError) throw error;

            throw new InternalServerError('Could not add or update skill.');
        }
    },

    async removeSkill(userId: string, skillId: string, actorId: string): Promise<void> {
        try {
            await validateUserActive(userId);

            const userProfile = await prisma.userProfile.findUnique({
                where: { userId },
                select: { id: true }
            });

            if (!userProfile) throw new NotFoundError('User profile');

            const { count } = await prisma.userSkill.deleteMany({
                where: { userProfileId: userProfile.id, skillId },
            });

            if (count === 0) {
                throw new NotFoundError("User's skill mapping");
            }

            userCache.delete(CACHE_KEYS.userSkills(userId));
            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_SKILL_REMOVED,
                actorId,
                metadata: { targetUserId: userId, skillId },
            });

            logger.info({ userId, actorId, skillId }, '[USER_SERVICE] Skill removed successfully');
        } catch (error) {
            logger.error({ err: error, userId, skillId }, '[USER_SERVICE] Failed to remove user skill');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not remove skill.');
        }
    },

    async bulkUpdateSkills(
        userId: string,
        skills: SkillData[],
        actorId: string
    ): Promise<UserSkill[]> {
        try {
            await validateUserActive(userId);

            const userProfile = await prisma.userProfile.upsert({
                where: { userId },
                update: {},
                create: { userId },
            });

            const skillIds = skills.map(s => s.skillId);
            const existingSkills = await prisma.skill.findMany({
                where: { id: { in: skillIds } },
            });

            if (existingSkills.length !== skillIds.length) {
                throw new ValidationError('One or more skills not found', []);
            }

            const updatedSkills = await prisma.$transaction(
                skills.map(({ skillId, level }) =>
                    prisma.userSkill.upsert({
                        where: {
                            userProfileId_skillId: {
                                userProfileId: userProfile.id,
                                skillId,
                            },
                        },
                        update: { level },
                        create: { userProfileId: userProfile.id, skillId, level },
                    })
                )
            );

            userCache.delete(CACHE_KEYS.userSkills(userId));
            invalidateUserCache(userId);

            await auditService.log({
                action: 'user:skills_bulk_updated',
                actorId,
                metadata: {
                    targetUserId: userId,
                    skillsCount: skills.length,
                    skills: skills.map(s => ({ skillId: s.skillId, level: s.level }))
                },
            });

            logger.info(
                { userId, actorId, count: skills.length },
                '[USER_SERVICE] Skills bulk updated successfully'
            );

            return updatedSkills;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to bulk update skills');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not bulk update skills.');
        }
    },

    // ROLE MANAGEMENT

    async assignRole(userId: string, role: Role, actorId: string) {
        try {
            const user = await this.getUserById(userId, false);

            if (user.roles.includes(role)) {
                logger.info({ userId, role }, '[USER_SERVICE] Role already assigned');
                return user;
            }

            const updatedUser = await prisma.user.update({
                where: { id: userId },
                data: { roles: { push: role } },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_ROLE_ASSIGNED,
                actorId,
                metadata: { targetUserId: userId, role },
            });

            logger.info({ userId, actorId, role }, '[USER_SERVICE] Role assigned successfully');

            return sanitizeUserData(updatedUser);
        } catch (error) {
            logger.error({ err: error, userId, role }, '[USER_SERVICE] Failed to assign role');
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'UserService', operation: 'assignRole' },
                extra: { userId, role }
            });

            throw new InternalServerError('Could not assign role.');
        }
    },

    async removeRole(userId: string, role: Role, actorId: string) {
        try {
            const user = await this.getUserById(userId, false);

            if (!user.roles.includes(role)) {
                logger.info({ userId, role }, '[USER_SERVICE] Role not present');
                return user;
            }

            if (role === 'SUPER_ADMIN') {
                const adminCount = await prisma.user.count({
                    where: { roles: { has: 'SUPER_ADMIN' }, isActive: true },
                });

                if (adminCount <= 1) {
                    throw new ForbiddenError('Cannot remove the last super admin role');
                }
            }

            const updatedRoles = user.roles.filter((r: Role) => r !== role);
            const updatedUser = await prisma.user.update({
                where: { id: userId },
                data: { roles: updatedRoles },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_ROLE_REMOVED,
                actorId,
                metadata: { targetUserId: userId, role },
            });

            logger.info({ userId, actorId, role }, '[USER_SERVICE] Role removed successfully');

            return sanitizeUserData(updatedUser);
        } catch (error) {
            logger.error({ err: error, userId, role }, '[USER_SERVICE] Failed to remove role');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not remove role.');
        }
    },

    async bulkAssignRoles(
        operation: BulkUserOperation,
        actorId: string
    ): Promise<{ success: number; failed: number; errors: any[] }> {
        const results = {
            success: 0,
            failed: 0,
            errors: [] as any[],
        };

        try {
            for (const userId of operation.userIds) {
                try {
                    await this.assignRole(userId, operation.role, actorId);
                    results.success++;
                } catch (error) {
                    results.failed++;
                    results.errors.push({
                        userId,
                        error: error instanceof Error ? error.message : 'Unknown error',
                    });
                }
            }

            await auditService.log({
                action: 'user:roles_bulk_assigned',
                actorId,
                metadata: {
                    role: operation.role,
                    totalUsers: operation.userIds.length,
                    success: results.success,
                    failed: results.failed,
                },
            });

            logger.info(
                { actorId, role: operation.role, results },
                '[USER_SERVICE] Bulk role assignment completed'
            );

            return results;
        } catch (error) {
            logger.error({ err: error, operation }, '[USER_SERVICE] Failed to bulk assign roles');
            throw new InternalServerError('Could not complete bulk role assignment.');
        }
    },

    // USER STATUS MANAGEMENT

    async deactivateUser(userId: string, reason: string, actorId: string) {
        try {
            const user = await this.getUserById(userId, false);

            if (user.roles.includes('SUPER_ADMIN')) {
                const adminCount = await prisma.user.count({
                    where: { roles: { has: 'SUPER_ADMIN' }, isActive: true },
                });

                if (adminCount <= 1) {
                    throw new ForbiddenError('Cannot deactivate the last super admin');
                }
            }

            const deactivatedUser = await prisma.user.update({
                where: { id: userId },
                data: {
                    isActive: false,
                    deactivatedAt: new Date(),
                    deactivationReason: reason
                },
            });

            await prisma.userSession.deleteMany({
                where: { userId },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_DEACTIVATED,
                actorId,
                metadata: { targetUserId: userId, reason },
            });

            logger.warn(
                { userId, actorId, reason },
                '[USER_SERVICE] User account deactivated'
            );

            return sanitizeUserData(deactivatedUser);
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to deactivate user');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not deactivate user.');
        }
    },

    async reactivateUser(userId: string, actorId: string) {
        try {
            const reactivatedUser = await prisma.user.update({
                where: { id: userId },
                data: {
                    isActive: true,
                    deactivatedAt: null,
                    deactivationReason: null
                },
            });

            invalidateUserCache(userId);

            await auditService.log({
                action: AUDIT_ACTIONS.USER_REACTIVATED,
                actorId,
                metadata: { targetUserId: userId },
            });

            logger.info({ userId, actorId }, '[USER_SERVICE] User account reactivated');

            return sanitizeUserData(reactivatedUser);
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to reactivate user');
            throw new InternalServerError('Could not reactivate user.');
        }
    },

    // DEVICE MANAGEMENT

    async getUserDevices(userId: string): Promise<UserDeviceDto[]> {
        try {
            const cacheKey = CACHE_KEYS.userDevices(userId);
            const cached = userCache.get(cacheKey);

            if (cached) return cached;

            const devices = await prisma.trustedDevice.findMany({
                where: { userId },
                orderBy: { lastUsedAt: 'desc' },
            });

            const deviceDtos = devices.map(({ userId, fingerprint, ...device }) => device);

            userCache.set(cacheKey, deviceDtos);
            return deviceDtos;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch user devices');
            throw new InternalServerError('Could not fetch devices.');
        }
    },

    async trustDevice(userId: string, deviceId: string, actorId: string): Promise<void> {
        try {
            const device = await prisma.trustedDevice.findFirst({
                where: { id: deviceId, userId },
            });
            if (!device) throw new NotFoundError('Device');

            const config = await prisma.appSetting.findUnique({
                where: { key: 'DEVICE_TRUST_DURATION_DAYS' },
            });
            const trustDurationDays = config?.value ? parseInt(config.value as string) : 30;

            await prisma.trustedDevice.update({
                where: { id: deviceId },
                data: {
                    isTrusted: true,
                    trustedAt: new Date(),
                    expiresAt: new Date(Date.now() + trustDurationDays * 24 * 60 * 60 * 1000),
                    revokedAt: null,
                },
            });

            userCache.delete(CACHE_KEYS.userDevices(userId));

            await auditService.log({
                action: AUDIT_ACTIONS.DEVICE_TRUSTED,
                actorId,
                metadata: { targetUserId: userId, deviceId },
            });

            logger.info({ userId, actorId, deviceId }, '[USER_SERVICE] Device trusted successfully');
        } catch (error) {
            logger.error({ err: error, userId, deviceId }, '[USER_SERVICE] Failed to trust device');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not trust device.');
        }
    },

    async revokeDevice(userId: string, deviceId: string, actorId: string): Promise<void> {
        try {
            const device = await prisma.trustedDevice.findFirst({
                where: { id: deviceId, userId },
            });

            if (!device) throw new NotFoundError('Device');

            await prisma.trustedDevice.update({
                where: { id: deviceId },
                data: {
                    isTrusted: false,
                    revokedAt: new Date(),
                    expiresAt: new Date()
                },
            });

            userCache.delete(CACHE_KEYS.userDevices(userId));

            await auditService.log({
                action: AUDIT_ACTIONS.DEVICE_REVOKED,
                actorId,
                metadata: { targetUserId: userId, deviceId },
            });

            logger.info({ userId, actorId, deviceId }, '[USER_SERVICE] Device revoked successfully');
        } catch (error) {
            logger.error({ err: error, userId, deviceId }, '[USER_SERVICE] Failed to revoke device');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not revoke device.');
        }
    },

    async revokeAllDevicesExcept(
        userId: string,
        currentDeviceId: string,
        actorId: string
    ): Promise<number> {
        try {
            const result = await prisma.trustedDevice.updateMany({
                where: {
                    userId,
                    id: { not: currentDeviceId },
                    isTrusted: true,
                },
                data: {
                    isTrusted: false,
                    revokedAt: new Date(),
                },
            });

            userCache.delete(CACHE_KEYS.userDevices(userId));

            await auditService.log({
                action: 'user:devices_bulk_revoked',
                actorId,
                metadata: { targetUserId: userId, count: result.count, exceptDeviceId: currentDeviceId },
            });

            logger.info(
                { userId, actorId, count: result.count },
                '[USER_SERVICE] Devices bulk revoked successfully'
            );

            return result.count;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to bulk revoke devices');
            throw new InternalServerError('Could not revoke devices.');
        }
    },

    // SEARCH & FILTERING

    async searchUsers(
        query: string,
        filters: UserSearchFilters = {},
        pagination: PaginationParams = {}
    ) {
        try {
            const { page = 1, limit = 20, sortBy = 'createdAt', sortOrder = 'desc' } = pagination;
            const skip = (page - 1) * limit;

            if (page < 1) throw new ValidationError('Page must be >= 1', []);
            if (limit < 1 || limit > 100) throw new ValidationError('Limit must be between 1 and 100', []);

            const where = buildUserWhereClause(filters);

            if (query) {
                where.OR = [
                    { profile: { firstName: { contains: query, mode: 'insensitive' } } },
                    { profile: { lastName: { contains: query, mode: 'insensitive' } } },
                    { email: { contains: query, mode: 'insensitive' } },
                    { username: { contains: query, mode: 'insensitive' } },
                ];
            }

            const [users, total] = await prisma.$transaction([
                prisma.user.findMany({
                    where,
                    include: {
                        profile: true,
                        _count: {
                            select: {
                                participantIn: true,
                            },
                        },
                    },
                    orderBy: { [sortBy]: sortOrder },
                    take: limit,
                    skip,
                }),
                prisma.user.count({ where }),
            ]);

            logger.info(
                { query, filters, total, page, limit },
                '[USER_SERVICE] User search completed'
            );

            return {
                data: users.map(sanitizeUserData),
                pagination: {
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                    hasNext: page * limit < total,
                    hasPrev: page > 1,
                },
            };
        } catch (error) {
            logger.error({ err: error, query, filters }, '[USER_SERVICE] Failed to search users');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not perform user search.');
        }
    },

    async getUsersByRole(
        role: Role,
        filters: Omit<UserSearchFilters, 'role'> = {},
        pagination: PaginationParams = {}
    ) {
        return this.searchUsers('', { ...filters, role: [role] }, pagination);
    },

    // STATISTICS & ANALYTICS

    async getUserStats(userId: string): Promise<UserStats> {
        try {
            const cacheKey = CACHE_KEYS.userStats(userId);
            const cached = userCache.get(cacheKey);

            if (cached) return cached;

            const user = await prisma.user.findUnique({
                where: { id: userId },
                include: {
                    profile: { select: { hoursVolunteered: true } },
                    onboarding: { select: { isCompleted: true } },
                },
            });

            if (!user) throw new NotFoundError('User');

            const [totalSkills, totalPrograms, totalEvents] = await prisma.$transaction([
                prisma.userSkill.count({ where: { profile: { userId } } }),
                prisma.programParticipant.count({ where: { userId } }),
                prisma.eventRegistration.count({ where: { userId } }),
            ]);

            const stats: UserStats = {
                totalSkills,
                totalHoursVolunteered: user.profile?.hoursVolunteered || 0,
                totalProgramsParticipated: totalPrograms,
                totalEventsAttended: totalEvents,
                onboardingCompleted: user.onboarding?.isCompleted || false,
                joinedAt: user.createdAt,
                lastLoginAt: user.lastLoginAt,
            };

            userCache.set(cacheKey, stats);
            return stats;
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch user stats');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not fetch user stats.');
        }
    },

    async getUserActivitySummary(userId: string, days: number = 30): Promise<UserActivitySummary> {
        try {
            const startDate = new Date();
            startDate.setDate(startDate.getDate() - days);

            const [logins, profileUpdates, skillsUpdated, programActivity] = await prisma.$transaction([
                prisma.auditLog.count({
                    where: {
                        actorId: userId,
                        action: AUDIT_ACTIONS.LOGIN_SUCCESS,
                        createdAt: { gte: startDate },
                    },
                }),
                prisma.auditLog.count({
                    where: {
                        actorId: userId,
                        action: AUDIT_ACTIONS.USER_PROFILE_UPDATED,
                        createdAt: { gte: startDate },
                    },
                }),
                prisma.auditLog.count({
                    where: {
                        actorId: userId,
                        action: { in: [AUDIT_ACTIONS.USER_SKILL_ADDED, AUDIT_ACTIONS.USER_SKILL_UPDATED] },
                        createdAt: { gte: startDate },
                    },
                }),
                prisma.programParticipant.count({
                    where: {
                        userId,
                        enrollmentDate: { gte: startDate },
                    },
                }),
            ]);

            return {
                period: { days, from: startDate, to: new Date() },
                activity: {
                    logins,
                    profileUpdates,
                    skillsUpdated,
                    programsJoined: programActivity,
                },
                lastActive: await this.getLastActiveDate(userId),
            };
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to fetch activity summary');
            throw new InternalServerError('Could not fetch activity summary.');
        }
    },

    async getLastActiveDate(userId: string): Promise<Date | null> {
        try {
            const [lastLogin, lastAudit] = await Promise.all([
                prisma.user.findUnique({
                    where: { id: userId },
                    select: { lastLoginAt: true },
                }),
                prisma.auditLog.findFirst({
                    where: { actorId: userId },
                    orderBy: { createdAt: 'desc' },
                    select: { createdAt: true },
                }),
            ]);

            const dates = [
                lastLogin?.lastLoginAt,
                lastAudit?.createdAt,
            ].filter((d): d is Date => d !== null && d !== undefined);

            if (dates.length === 0) return null;

            return new Date(Math.max(...dates.map(d => d.getTime())));
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to get last active date');
            return null;
        }
    },

    // DATA EXPORT & GDPR

    async exportUserData(userId: string): Promise<UserExportData> {
        try {
            const [user, skills, devices, stats, sessions, auditLogs] = await Promise.all([
                this.getUserById(userId),
                this.getUserSkills(userId),
                this.getUserDevices(userId),
                this.getUserStats(userId),
                prisma.userSession.findMany({
                    where: { userId },
                    orderBy: { createdAt: 'desc' },
                    take: 50,
                    select: {
                        id: true,
                        createdAt: true,
                        expiresAt: true,
                        ipAddress: true,
                        userAgent: true,
                    }
                }),
                prisma.auditLog.findMany({
                    where: { actorId: userId },
                    orderBy: { createdAt: 'desc' },
                    take: 100,
                    select: {
                        action: true,
                        createdAt: true,
                        meta: true,
                    }
                }),
            ]);

            return {
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    roles: user.roles,
                    createdAt: user.createdAt,
                    emailVerified: user.emailVerified,
                    lastLoginAt: user.lastLoginAt,
                },
                profile: user.profile,
                preferences: user.preferences,
                skills,
                devices,
                stats,
                sessions: sessions.map(s => ({
                    id: s.id,
                    createdAt: s.createdAt,
                    expiresAt: s.expiresAt,
                    ipAddress: s.ipAddress,
                    userAgent: s.userAgent,
                })),
                auditLogs: auditLogs.map(log => ({
                    action: log.action,
                    createdAt: log.createdAt,
                    metadata: log.meta,
                })),
                exportedAt: new Date().toISOString(),
            };
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to export user data');
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'UserService', operation: 'exportUserData' },
                extra: { userId }
            });

            throw new InternalServerError('Could not export user data.');
        }
    },

    async deleteUserAccount(userId: string, actorId: string, reason?: string): Promise<void> {
        try {
            const user = await this.getUserById(userId, false);

            if (user.roles.includes('SUPER_ADMIN')) {
                const adminCount = await prisma.user.count({
                    where: { roles: { has: 'SUPER_ADMIN' }, isActive: true },
                });

                if (adminCount <= 1) {
                    throw new ForbiddenError('Cannot delete the last super admin');
                }
            }

            const exportedData = await this.exportUserData(userId);

            await auditService.log({
                action: 'user:account_deleted',
                actorId,
                metadata: {
                    targetUserId: userId,
                    reason,
                    dataExported: true,
                    timestamp: new Date().toISOString(),
                },
            });

            await prisma.$transaction([
                prisma.userSession.deleteMany({ where: { userId } }),
                prisma.token.deleteMany({ where: { userId } }),
                prisma.trustedDevice.deleteMany({ where: { userId } }),
                prisma.failedLoginAttempt.deleteMany({ where: { email: user.email } }),
                prisma.auditLog.updateMany({
                    where: { actorId: userId },
                    data: {
                        actorId: null,
                        meta: { anonymized: true, originalUserId: userId } as any,
                    },
                }),
                prisma.user.delete({ where: { id: userId } }),
            ]);

            invalidateUserCache(userId);

            logger.warn(
                { userId, actorId, reason },
                '[USER_SERVICE] User account deleted permanently'
            );
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to delete user account');
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'UserService', operation: 'deleteUserAccount', severity: 'high' },
                extra: { userId, reason }
            });

            throw new InternalServerError('Could not delete user account.');
        }
    },

    async anonymizeUserData(userId: string, actorId: string): Promise<void> {
        try {
            const anonymousEmail = `deleted_${userId}@anonymized.local`;
            const anonymousName = 'Deleted User';

            await prisma.$transaction([
                prisma.user.update({
                    where: { id: userId },
                    data: {
                        email: anonymousEmail,
                        username: null,
                        avatar: null,
                        isActive: false,
                        deactivatedAt: new Date(),
                        deactivationReason: 'Account anonymized by user request',
                    },
                }),
                prisma.userProfile.update({
                    where: { userId },
                    data: {
                        firstName: anonymousName,
                        lastName: '',
                        bio: null,
                        phone: null,
                        city: null,
                        country: null,
                        birthDate: null,
                        jobTitle: null,
                        company: null,
                        linkedin: null,
                        twitter: null,
                        avatarUrl: null,
                        interests: [],
                    },
                }),
                prisma.userSession.deleteMany({ where: { userId } }),
                prisma.trustedDevice.deleteMany({ where: { userId } }),
            ]);

            invalidateUserCache(userId);

            await auditService.log({
                action: 'user:data_anonymized',
                actorId,
                metadata: { targetUserId: userId },
            });

            logger.info({ userId, actorId }, '[USER_SERVICE] User data anonymized successfully');
        } catch (error) {
            logger.error({ err: error, userId }, '[USER_SERVICE] Failed to anonymize user data');
            throw new InternalServerError('Could not anonymize user data.');
        }
    },

    // ADMIN OPERATIONS

    async getPlatformUserStats() {
        try {
            const [
                totalUsers,
                activeUsers,
                verifiedUsers,
                usersLast30Days,
                usersByRole,
            ] = await Promise.all([
                prisma.user.count(),
                prisma.user.count({ where: { isActive: true } }),
                prisma.user.count({ where: { isVerified: true } }),
                prisma.user.count({
                    where: {
                        createdAt: {
                            gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000),
                        },
                    },
                }),
                prisma.user.groupBy({
                    by: ['roles'],
                    _count: true,
                }),
            ]);

            return {
                total: totalUsers,
                active: activeUsers,
                verified: verifiedUsers,
                newLast30Days: usersLast30Days,
                byRole: usersByRole,
                inactiveRate: ((totalUsers - activeUsers) / totalUsers) * 100,
                verificationRate: (verifiedUsers / totalUsers) * 100,
            };
        } catch (error) {
            logger.error({ err: error }, '[USER_SERVICE] Failed to fetch platform stats');
            throw new InternalServerError('Could not fetch platform statistics.');
        }
    },

    async getPendingVerificationUsers(pagination: PaginationParams = {}) {
        return this.searchUsers('', { isActive: true }, pagination);
    },

    // CACHE MANAGEMENT    
    clearUserCache(userId: string): void {
        invalidateUserCache(userId);
        logger.debug({ userId }, '[USER_SERVICE] User cache cleared');
    },

    clearAllCaches(): void {
        userCache.clear();
        logger.info('[USER_SERVICE] All user caches cleared');
    },

    getCacheStats() {
        return {
            size: userCache.size,
            max: userCache.max,
            calculatedSize: userCache.calculatedSize,
        };
    },
};