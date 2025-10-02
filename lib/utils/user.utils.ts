// lib/utils/user.utils.ts
import { Prisma, User, Role } from '@prisma/client';
import { UserSearchFilters } from '@/types/user.types';

/**
 * Sanitize user data by removing sensitive fields
 */
export const sanitizeUserData = <T extends Partial<User>>(
    user: T
): Omit<T, 'hashedPassword' | 'mfaSecret'> => {
    const { hashedPassword, mfaSecret, ...sanitized } = user as User;
    return sanitized as Omit<T, 'hashedPassword' | 'mfaSecret'>;
};

/**
 * Build Prisma where clause from search filters
 */
export const buildUserWhereClause = (filters: UserSearchFilters): Prisma.UserWhereInput => {
    const where: Prisma.UserWhereInput = {};

    // Role filter
    if (filters.role?.length) {
        where.roles = { hasSome: filters.role };
    }

    // Active status filter
    if (filters.isActive !== undefined) {
        where.isActive = filters.isActive;
    }

    // Verified status filter
    if (filters.isVerified !== undefined) {
        where.isVerified = filters.isVerified;
    }

    // Date range filters
    if (filters.createdAfter || filters.createdBefore) {
        where.createdAt = {};
        if (filters.createdAfter) {
            where.createdAt.gte = filters.createdAfter;
        }
        if (filters.createdBefore) {
            where.createdAt.lte = filters.createdBefore;
        }
    }

    // Program participation filter
    if (filters.programId) {
        where.participantIn = {
            some: {
                programId: filters.programId,
            },
        };
    }

    // Profile filters
    const profileWhere: Prisma.UserProfileWhereInput = {};

    if (filters.location) {
        profileWhere.OR = [
            { city: { contains: filters.location, mode: 'insensitive' } },
            { country: { contains: filters.location, mode: 'insensitive' } },
        ];
    }

    if (filters.skills?.length) {
        profileWhere.skills = {
            some: {
                skill: {
                    key: { in: filters.skills },
                },
            },
        };
    }

    if (Object.keys(profileWhere).length > 0) {
        where.profile = profileWhere;
    }

    return where;
};

/**
 * Validate if user has specific role
 */
export const hasRole = (user: { roles: Role[] }, role: Role): boolean => {
    return user.roles.includes(role);
};

/**
 * Validate if user has any of the specified roles
 */
export const hasAnyRole = (user: { roles: Role[] }, roles: Role[]): boolean => {
    return roles.some(role => user.roles.includes(role));
};

/**
 * Validate if user has all of the specified roles
 */
export const hasAllRoles = (user: { roles: Role[] }, roles: Role[]): boolean => {
    return roles.every(role => user.roles.includes(role));
};

/**
 * Check if user is an admin
 */
export const isAdmin = (user: { roles: Role[] }): boolean => {
    const adminRoles: Role[] = [
        'SUPER_ADMIN',
        'EXECUTIVE_DIRECTOR',
        'PROGRAM_MANAGER',
        'CONTENT_MANAGER',
        'FINANCE_MANAGER',
    ];
    return hasAnyRole(user, adminRoles);
};

/**
 * Format user display name
 */
export const getUserDisplayName = (user: {
    profile?: { firstName?: string | null; lastName?: string | null } | null;
    username?: string | null;
    email?: string;
}): string => {
    if (user.profile?.firstName && user.profile?.lastName) {
        return `${user.profile.firstName} ${user.profile.lastName}`;
    }
    if (user.profile?.firstName) {
        return user.profile.firstName;
    }
    if (user.username) {
        return user.username;
    }
    return user.email?.split('@')[0] || 'Unknown User';
};

/**
 * Get user initials for avatar fallback
 */
export const getUserInitials = (user: {
    profile?: { firstName?: string | null; lastName?: string | null } | null;
    username?: string | null;
    email?: string;
}): string => {
    if (user.profile?.firstName && user.profile?.lastName) {
        return `${user.profile.firstName[0]}${user.profile.lastName[0]}`.toUpperCase();
    }
    if (user.profile?.firstName) {
        return user.profile.firstName.substring(0, 2).toUpperCase();
    }
    if (user.username) {
        return user.username.substring(0, 2).toUpperCase();
    }
    if (user.email) {
        return user.email.substring(0, 2).toUpperCase();
    }
    return 'U';
};

/**
 * Calculate user account age in days
 */
export const getUserAccountAge = (createdAt: Date): number => {
    const now = new Date();
    const diff = now.getTime() - createdAt.getTime();
    return Math.floor(diff / (1000 * 60 * 60 * 24));
};

/**
 * Validate phone number format
 */
export const isValidPhoneNumber = (phone: string): boolean => {
    const phoneRegex = /^[+]?[\d\s-()]{10,20}$/;
    return phoneRegex.test(phone);
};