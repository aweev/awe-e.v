// types/program.types.ts
import { z } from 'zod';
import {
    Program,
    ProgramCategory,
    ProgramEnrolment,
    ProgramParticipant,
    ProgramStatus,
    EnrolmentStatus
} from '@prisma/client';

// ============================================================================
// VALIDATION SCHEMAS
// ============================================================================

export const createProgramCategorySchema = z.object({
    slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/),
    name: z.record(z.string(), z.string().min(1).max(200)),
    description: z.record(z.string(), z.string().max(1000)),
    tagline: z.record(z.string(), z.string().max(200)).optional(),
    heroImageUrl: z.string().url().optional().nullable(),
    iconName: z.string().min(1).max(50),
    color: z.string().regex(/^#[0-9A-F]{6}$/i),
    displayOrder: z.number().int().min(0).default(0),
});

export const updateProgramCategorySchema = createProgramCategorySchema.partial();

export const createProgramSchema = z.object({
    slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/),
    categoryId: z.string().cuid(),
    status: z.nativeEnum(ProgramStatus).default('DRAFT'),

    // Multi-language fields
    name: z.record(z.string(), z.string().min(1).max(200)),
    description: z.record(z.string(), z.string().min(1)),
    tagline: z.record(z.string(), z.string().max(200)).optional(),
    content: z.record(z.string(), z.any()),

    // Media
    heroImageUrl: z.string().url().optional().nullable(),
    thumbnailUrl: z.string().url().optional().nullable(),
    videoThumbnailUrl: z.string().url().optional().nullable(),
    mediaGallery: z.array(z.string().url()).default([]),

    // Metadata
    tags: z.array(z.string()).default([]),
    metrics: z.array(z.any()).default([]),
    curriculum: z.array(z.any()).default([]),
    eligibilityCriteria: z.array(z.any()).default([]),
    applicationSteps: z.array(z.any()).default([]),

    // Program details
    duration: z.string().optional().nullable(),
    capacity: z.number().int().positive().optional().nullable(),
    applicationDeadline: z.coerce.date().optional().nullable(),
    startDate: z.coerce.date().optional().nullable(),
    endDate: z.coerce.date().optional().nullable(),

    // Requirements
    minAge: z.number().int().min(0).max(120).optional().nullable(),
    maxAge: z.number().int().min(0).max(120).optional().nullable(),
    requiredDocs: z.array(z.string()).default([]),
    requiredSkills: z.array(z.string()).default([]),
    cost: z.number().optional().nullable(),
    currency: z.string().length(3).default('EUR'),

    // SEO
    seo: z.record(z.string(), z.any()).optional().nullable(),
});

export const updateProgramSchema = createProgramSchema.partial().extend({
    slug: z.string().min(1).max(100).regex(/^[a-z0-9-]+$/).optional(),
});

export const createEnrolmentSchema = z.object({
    programId: z.string().cuid(),
    answers: z.record(z.string(), z.any()).default({}),
    docs: z.record(z.string(), z.any()).default({}),
    metadata: z.record(z.string(), z.any()).default({}),
});

export const updateEnrolmentSchema = z.object({
    status: z.nativeEnum(EnrolmentStatus).optional(),
    step: z.number().int().min(0).optional(),
    answers: z.record(z.string(), z.any()).optional(),
    docs: z.record(z.string(), z.any()).optional(),
    metadata: z.record(z.string(), z.any()).optional(),
});

export const createParticipantSchema = z.object({
    programId: z.string().cuid(),
    userId: z.string().cuid(),
    status: z.string().default('enrolled'),
    notes: z.string().max(2000).optional().nullable(),
});

export const updateParticipantSchema = z.object({
    status: z.string().optional(),
    completionDate: z.coerce.date().optional().nullable(),
    outcomes: z.record(z.string(), z.any()).optional().nullable(),
    notes: z.string().max(2000).optional().nullable(),
});

// ============================================================================
// TYPE DEFINITIONS
// ============================================================================

export type CreateProgramCategoryData = z.infer<typeof createProgramCategorySchema>;
export type UpdateProgramCategoryData = z.infer<typeof updateProgramCategorySchema>;
export type CreateProgramData = z.infer<typeof createProgramSchema>;
export type UpdateProgramData = z.infer<typeof updateProgramSchema>;
export type CreateEnrolmentData = z.infer<typeof createEnrolmentSchema>;
export type UpdateEnrolmentData = z.infer<typeof updateEnrolmentSchema>;
export type CreateParticipantData = z.infer<typeof createParticipantSchema>;
export type UpdateParticipantData = z.infer<typeof updateParticipantSchema>;

// Search and filtering
export interface ProgramSearchFilters {
    categoryId?: string;
    status?: ProgramStatus[];
    tags?: string[];
    minAge?: number;
    maxAge?: number;
    hasCapacity?: boolean;
    isOpenForApplication?: boolean;
    startDateAfter?: Date;
    startDateBefore?: Date;
}

export interface EnrolmentSearchFilters {
    programId?: string;
    userId?: string;
    status?: EnrolmentStatus[];
    submittedAfter?: Date;
    submittedBefore?: Date;
}

export interface ParticipantSearchFilters {
    programId?: string;
    status?: string[];
    enrolledAfter?: Date;
    completedAfter?: Date;
    hasOutcomes?: boolean;
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

// Extended types with relations
export interface ProgramWithCategory extends Program {
    category: ProgramCategory;
    _count?: {
        enrolments: number;
        participants: number;
    };
}

export interface EnrolmentWithRelations extends ProgramEnrolment {
    program: Program;
    user: {
        id: string;
        email: string;
        profile: {
            firstName: string | null;
            lastName: string | null;
        } | null;
    };
}

export interface ParticipantWithRelations extends ProgramParticipant {
    program: Program;
    user: {
        id: string;
        email: string;
        profile: {
            firstName: string | null;
            lastName: string | null;
            avatarUrl: string | null;
        } | null;
    };
}

// Statistics
export interface ProgramStats {
    totalEnrolments: number;
    activeParticipants: number;
    completedParticipants: number;
    completionRate: number;
    averageDuration: number | null;
    capacityUtilization: number | null;
}

export interface CategoryStats {
    totalPrograms: number;
    activePrograms: number;
    totalParticipants: number;
    popularPrograms: Array<{
        id: string;
        name: any;
        participantCount: number;
    }>;
}

// Application workflow
export interface ApplicationEligibility {
    isEligible: boolean;
    reasons: string[];
    requirements: {
        met: string[];
        unmet: string[];
    };
}

export interface ApplicationProgress {
    currentStep: number;
    totalSteps: number;
    completedSteps: number;
    nextStep: {
        name: string;
        description: string;
        required: boolean;
    } | null;
}

// Bulk operations
export interface BulkEnrolmentOperation {
    enrolmentIds: string[];
    action: 'approve' | 'reject' | 'archive';
    reason?: string;
}

export interface BulkParticipantOperation {
    participantIds: string[];
    action: 'graduate' | 'withdraw' | 'suspend';
    reason?: string;
}