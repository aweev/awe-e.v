// types/user.types.ts
import { z } from 'zod';
import { Role, SkillLevel, TrustedDevice, UserProfile, UserPreferences, User } from '@prisma/client';

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

export const updateProfileSchema = z.object({
    firstName: z.string().min(1, 'First name is required').max(50).optional(),
    lastName: z.string().min(1, 'Last name is required').max(50).optional(),
    bio: z.string().max(500, 'Bio must be 500 characters or less').optional().nullable(),
    phone: z.string()
        .regex(/^[+]?[\d\s-()]*$/, 'Invalid phone number format')
        .min(10, 'Phone number too short')
        .max(20, 'Phone number too long')
        .optional()
        .nullable(),
    city: z.string().max(100).optional().nullable(),
    country: z.string().max(100).optional().nullable(),
    birthDate: z.coerce.date()
        .max(new Date(), 'Birth date cannot be in the future')
        .refine(
            (date) => {
                const age = new Date().getFullYear() - date.getFullYear();
                return age >= 13 && age <= 120;
            },
            'Age must be between 13 and 120 years'
        )
        .optional()
        .nullable(),
    jobTitle: z.string().max(100).optional().nullable(),
    company: z.string().max(100).optional().nullable(),
    linkedin: z.string()
        .url('Invalid LinkedIn URL')
        .refine(
            (url) => url.includes('linkedin.com'),
            'Must be a LinkedIn URL'
        )
        .or(z.literal(''))
        .optional()
        .nullable(),
    twitter: z.string()
        .url('Invalid Twitter URL')
        .refine(
            (url) => url.includes('twitter.com') || url.includes('x.com'),
            'Must be a Twitter/X URL'
        )
        .or(z.literal(''))
        .optional()
        .nullable(),
    interests: z.array(z.string().max(50))
        .max(20, 'Maximum 20 interests allowed')
        .optional(),
    avatarUrl: z.string()
        .url('Invalid avatar URL')
        .or(z.literal(''))
        .optional()
        .nullable(),
});

export const updatePreferencesSchema = z.object({
    // Notification preferences
    emailNotifications: z.boolean().optional(),
    smsNotifications: z.boolean().optional(),
    pushNotifications: z.boolean().optional(),
    marketingEmails: z.boolean().optional(),
    newsletterSubscription: z.boolean().optional(),

    // Appearance preferences
    theme: z.enum(['light', 'dark', 'system']).optional(),
    language: z.enum(['en', 'de', 'fr']).optional(),

    // Localization
    timezone: z.string().optional(),
    dateFormat: z.string().optional(),
    timeFormat: z.enum(['12h', '24h']).optional(),

    // Privacy preferences
    profileVisibility: z.enum(['PRIVATE', 'INTERNAL', 'PUBLIC']).optional(),
    showEmail: z.boolean().optional(),
    showPhoneNumber: z.boolean().optional(),
    showLocation: z.boolean().optional(),

    // Content preferences
    contentLanguage: z.array(z.string()).max(5).optional(),
    contentTopics: z.array(z.string()).max(10).optional(),
});

export const skillSchema = z.object({
    skillId: z.string().cuid('Invalid skill ID'),
    level: z.nativeEnum(SkillLevel),
});

// Bulk operations
export const bulkUserOperationSchema = z.object({
    userIds: z.array(z.string().cuid()).min(1).max(100),
    role: z.nativeEnum(Role),
});

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export type UpdateProfileData = z.infer<typeof updateProfileSchema>;
export type UpdatePreferencesData = z.infer<typeof updatePreferencesSchema>;
export type SkillData = z.infer<typeof skillSchema>;
export type BulkUserOperation = z.infer<typeof bulkUserOperationSchema>;

// Search and filtering
export interface UserSearchFilters {
    role?: Role[];
    skills?: string[];
    location?: string;
    isActive?: boolean;
    programId?: string;
    isVerified?: boolean;
    createdAfter?: Date;
    createdBefore?: Date;
}

export interface PaginationParams {
    page?: number;
    limit?: number;
    sortBy?: string;
    sortOrder?: 'asc' | 'desc';
}

export interface PaginationResult<T> {
    data: T[];
    pagination: {
        page: number;
        limit: number;
        total: number;
        totalPages: number;
        hasNext: boolean;
        hasPrev: boolean;
    };
}

// Device management
export type UserDeviceDto = Omit<TrustedDevice, 'userId' | 'fingerprint'>;

// Statistics
export interface UserStats {
    totalSkills: number;
    totalHoursVolunteered: number;
    totalProgramsParticipated: number;
    totalEventsAttended: number;
    onboardingCompleted: boolean;
    joinedAt: Date;
    lastLoginAt: Date | null;
}

export interface UserActivitySummary {
    period: {
        days: number;
        from: Date;
        to: Date;
    };
    activity: {
        logins: number;
        profileUpdates: number;
        skillsUpdated: number;
        programsJoined: number;
    };
    lastActive: Date | null;
}

export interface ProfileCompletionStatus {
    percentage: number;
    requiredFields: {
        total: number;
        completed: number;
        missing: string[];
    };
    optionalFields: {
        total: number;
        completed: number;
        missing: string[];
    };
    isComplete: boolean;
}

// GDPR Export
export interface UserExportData {
    user: {
        id: string;
        email: string;
        username: string | null;
        roles: Role[];
        createdAt: Date;
        emailVerified: Date | null;
        lastLoginAt: Date | null;
    };
    profile: UserProfile | null;
    preferences: UserPreferences | null;
    skills: any[];
    devices: UserDeviceDto[];
    stats: UserStats;
    sessions: Array<{
        id: string;
        createdAt: Date;
        expiresAt: Date;
        ipAddress: string | null;
        userAgent: string | null;
    }>;
    auditLogs: Array<{
        action: string;
        createdAt: Date;
        metadata: any;
    }>;
    exportedAt: string;
}