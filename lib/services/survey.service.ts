// lib/services/survey.service.ts
import { prisma } from '@/lib/db';
import { logger } from '@/lib/logger';
import { auditService } from '@/lib/services/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import {
    AppError,
    ForbiddenError,
    InternalServerError,
    NotFoundError,
    ValidationError
} from '@/lib/errors/errors';
import { LRUCache } from 'lru-cache';
import * as Sentry from '@sentry/nextjs';
import { z } from 'zod';
import type { Locale } from '@/lib/i18n';
import { Prisma, SurveyQuestion } from '@prisma/client';

// ============================================================================
// TYPES & SCHEMAS
// ============================================================================

export interface CreateSurveyData {
    title: Record<Locale, string>;
    description?: Record<Locale, string>;
    type?: string;
    isActive?: boolean;
    isAnonymous?: boolean;
    targetAudience?: string[];
    programId?: string;
    startDate?: Date;
    endDate?: Date;
    questions: CreateQuestionData[];
}

export interface CreateQuestionData {
    question: Record<Locale, string>;
    type: 'text' | 'textarea' | 'radio' | 'checkbox' | 'rating' | 'scale';
    options?: Record<Locale, string[]>;
    isRequired?: boolean;
    order?: number;
    showIf?: any;
}

export interface SubmitResponseData {
    surveyId: string;
    answers: Record<string, any>;
    isComplete?: boolean;
}

export interface SurveyFilters {
    type?: string;
    isActive?: boolean;
    programId?: string;
    startDate?: Date;
    endDate?: Date;
}

export interface SurveyAnalytics {
    totalResponses: number;
    completedResponses: number;
    averageCompletionTime: number;
    completionRate: number;
    responsesByDate: Array<{ date: string; count: number }>;
    questionAnalytics: Array<{
        questionId: string;
        question: any;
        responses: number;
        answers: any;
    }>;
}

const createSurveySchema = z.object({
    title: z.record(z.string(), z.string()), // keys: string, values: string
    description: z.record(z.string(), z.string()).optional(),
    type: z.string().default("feedback"),
    isActive: z.boolean().default(true),
    isAnonymous: z.boolean().default(false),
    targetAudience: z.array(z.string()).optional(),
    programId: z.string().optional(),
    startDate: z.coerce.date().optional(),
    endDate: z.coerce.date().optional(),
    questions: z.array(z.object({
        question: z.record(z.string(), z.string()), // same fix here
        type: z.enum(["text", "textarea", "radio", "checkbox", "rating", "scale"]),
        options: z.record(z.string(), z.array(z.string())).optional(), // key: string, value: array of strings
        isRequired: z.boolean().default(false),
        order: z.number().default(0),
        showIf: z.any().optional(),
    })).min(1, "At least one question is required"),
});

const submitResponseSchema = z.object({
    surveyId: z.string().cuid(),
    answers: z.record(z.string(), z.any()), // key: string, value: any
    isComplete: z.boolean().default(true),
});


// ============================================================================
// CACHING
// ============================================================================

const surveyCache = new LRUCache<string, any>({
    max: 200,
    ttl: 1000 * 60 * 10, // 10 minutes
});

const CACHE_KEYS = {
    survey: (id: string) => `survey:${id}`,
    surveyQuestions: (id: string) => `survey:${id}:questions`,
    surveyResponses: (id: string) => `survey:${id}:responses`,
    surveyAnalytics: (id: string) => `survey:${id}:analytics`,
};

function invalidateSurveyCache(surveyId: string): void {
    surveyCache.delete(CACHE_KEYS.survey(surveyId));
    surveyCache.delete(CACHE_KEYS.surveyQuestions(surveyId));
    surveyCache.delete(CACHE_KEYS.surveyResponses(surveyId));
    surveyCache.delete(CACHE_KEYS.surveyAnalytics(surveyId));
}

// ============================================================================
// SURVEY SERVICE
// ============================================================================

export const surveyService = {
    // ========================================================================
    // CREATE & UPDATE
    // ========================================================================

    /**
     * Create a new survey with questions
     */
    async createSurvey(data: CreateSurveyData, actorId: string) {
        try {
            const validatedData = createSurveySchema.parse(data);

            // Validate date range
            if (validatedData.startDate && validatedData.endDate) {
                if (validatedData.endDate < validatedData.startDate) {
                    throw new ValidationError('End date must be after start date', []);
                }
            }

            const survey = await prisma.survey.create({
                data: {
                    title: validatedData.title as any,
                    description: validatedData.description as any,
                    type: validatedData.type,
                    isActive: validatedData.isActive,
                    isAnonymous: validatedData.isAnonymous,
                    targetAudience: validatedData.targetAudience || [],
                    programId: validatedData.programId,
                    startDate: validatedData.startDate,
                    endDate: validatedData.endDate,
                    questions: {
                        create: validatedData.questions.map((q, index) => ({
                            question: q.question as any,
                            type: q.type,
                            options: q.options as any,
                            isRequired: q.isRequired,
                            order: q.order ?? index,
                            showIf: q.showIf as any,
                        })),
                    },
                },
                include: {
                    questions: {
                        orderBy: { order: 'asc' },
                    },
                },
            });

            await auditService.log({
                action: 'survey:created' as any,
                actorId,
                metadata: {
                    surveyId: survey.id,
                    type: survey.type,
                    questionCount: survey.questions.length,
                },
            });

            logger.info(
                { surveyId: survey.id, actorId },
                '[SURVEY_SERVICE] Survey created successfully'
            );

            return survey;
        } catch (error) {
            logger.error({ err: error, data }, '[SURVEY_SERVICE] Failed to create survey');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid survey data', error.issues);
            }
            if (error instanceof AppError) throw error;

            Sentry.captureException(error, {
                tags: { module: 'SurveyService', operation: 'createSurvey' },
                extra: { data },
            });

            throw new InternalServerError('Could not create survey.');
        }
    },

    /**
     * Update survey details (not questions)
     */
    async updateSurvey(
        surveyId: string,
        data: Partial<CreateSurveyData>,
        actorId: string
    ) {
        try {
            const existingSurvey = await prisma.survey.findUnique({
                where: { id: surveyId },
            });

            if (!existingSurvey) {
                throw new NotFoundError('Survey');
            }

            const updatedSurvey = await prisma.survey.update({
                where: { id: surveyId },
                data: {
                    title: data.title as any,
                    description: data.description as any,
                    type: data.type,
                    isActive: data.isActive,
                    isAnonymous: data.isAnonymous,
                    targetAudience: data.targetAudience,
                    programId: data.programId,
                    startDate: data.startDate,
                    endDate: data.endDate,
                },
                include: {
                    questions: {
                        orderBy: { order: 'asc' },
                    },
                },
            });

            invalidateSurveyCache(surveyId);

            await auditService.log({
                action: 'survey:updated' as any,
                actorId,
                metadata: {
                    surveyId,
                    updatedFields: Object.keys(data),
                },
            });

            logger.info(
                { surveyId, actorId },
                '[SURVEY_SERVICE] Survey updated successfully'
            );

            return updatedSurvey;
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to update survey');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not update survey.');
        }
    },

    /**
     * Add question to existing survey
     */
    async addQuestion(
        surveyId: string,
        questionData: CreateQuestionData,
        actorId: string
    ) {
        try {
            const survey = await prisma.survey.findUnique({
                where: { id: surveyId },
                include: { questions: true },
            });

            if (!survey) {
                throw new NotFoundError('Survey');
            }

            const nextOrder = Math.max(...survey.questions.map(q => q.order), -1) + 1;

            const question = await prisma.surveyQuestion.create({
                data: {
                    surveyId,
                    question: questionData.question as any,
                    type: questionData.type,
                    options: questionData.options as any,
                    isRequired: questionData.isRequired ?? false,
                    order: questionData.order ?? nextOrder,
                    showIf: questionData.showIf as any,
                },
            });

            invalidateSurveyCache(surveyId);

            await auditService.log({
                action: 'survey:question_added' as any,
                actorId,
                metadata: { surveyId, questionId: question.id },
            });

            return question;
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to add question');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not add question.');
        }
    },

    /**
     * Update existing question
     */
    async updateQuestion(
        questionId: string,
        data: Partial<CreateQuestionData>,
        actorId: string
    ) {
        try {
            const question = await prisma.surveyQuestion.update({
                where: { id: questionId },
                data: {
                    question: data.question as any,
                    type: data.type,
                    options: data.options as any,
                    isRequired: data.isRequired,
                    order: data.order,
                    showIf: data.showIf as any,
                },
            });

            invalidateSurveyCache(question.surveyId);

            await auditService.log({
                action: 'survey:question_updated' as any,
                actorId,
                metadata: { questionId, surveyId: question.surveyId },
            });

            return question;
        } catch (error) {
            logger.error({ err: error, questionId }, '[SURVEY_SERVICE] Failed to update question');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not update question.');
        }
    },

    /**
     * Delete question
     */
    async deleteQuestion(questionId: string, actorId: string) {
        try {
            const question = await prisma.surveyQuestion.findUnique({
                where: { id: questionId },
            });

            if (!question) {
                throw new NotFoundError('Question');
            }

            await prisma.surveyQuestion.delete({
                where: { id: questionId },
            });

            invalidateSurveyCache(question.surveyId);

            await auditService.log({
                action: 'survey:question_deleted' as any,
                actorId,
                metadata: { questionId, surveyId: question.surveyId },
            });

            logger.info(
                { questionId, actorId },
                '[SURVEY_SERVICE] Question deleted successfully'
            );
        } catch (error) {
            logger.error({ err: error, questionId }, '[SURVEY_SERVICE] Failed to delete question');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not delete question.');
        }
    },

    // ========================================================================
    // READ OPERATIONS
    // ========================================================================

    /**
     * Get survey by ID with questions
     */
    async getSurveyById(surveyId: string, includeQuestions = true) {
        try {
            const cacheKey = CACHE_KEYS.survey(surveyId);
            const cached = surveyCache.get(cacheKey);

            if (cached) return cached;

            const survey = await prisma.survey.findUnique({
                where: { id: surveyId },
                include: includeQuestions
                    ? {
                        questions: {
                            orderBy: { order: 'asc' },
                        },
                    }
                    : undefined,
            });

            if (!survey) {
                throw new NotFoundError('Survey');
            }

            surveyCache.set(cacheKey, survey);
            return survey;
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to get survey');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not fetch survey.');
        }
    },

    /**
     * List surveys with filters and pagination
     */
    async listSurveys(
        filters: SurveyFilters = {},
        pagination: { page?: number; limit?: number } = {}
    ) {
        try {
            const { page = 1, limit = 20 } = pagination;
            const skip = (page - 1) * limit;

            const where: Prisma.SurveyWhereInput = {};

            if (filters.type) where.type = filters.type;
            if (filters.isActive !== undefined) where.isActive = filters.isActive;
            if (filters.programId) where.programId = filters.programId;

            if (filters.startDate || filters.endDate) {
                where.OR = [
                    {
                        startDate: {
                            gte: filters.startDate,
                            lte: filters.endDate,
                        },
                    },
                    {
                        endDate: {
                            gte: filters.startDate,
                            lte: filters.endDate,
                        },
                    },
                ];
            }

            const [surveys, total] = await prisma.$transaction([
                prisma.survey.findMany({
                    where,
                    include: {
                        questions: {
                            orderBy: { order: 'asc' },
                        },
                        _count: {
                            select: {
                                responses: true,
                            },
                        },
                    },
                    orderBy: { createdAt: 'desc' },
                    skip,
                    take: limit,
                }),
                prisma.survey.count({ where }),
            ]);

            return {
                data: surveys,
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
            logger.error({ err: error, filters }, '[SURVEY_SERVICE] Failed to list surveys');
            throw new InternalServerError('Could not list surveys.');
        }
    },

    // ========================================================================
    // RESPONSE MANAGEMENT
    // ========================================================================

    /**
     * Submit survey response
     */
    async submitResponse(
        data: SubmitResponseData,
        userId?: string,
        metadata?: { ipAddress?: string; userAgent?: string }
    ) {
        try {
            const validatedData = submitResponseSchema.parse(data);

            const survey = await this.getSurveyById(validatedData.surveyId);

            // Check if survey is active
            if (!survey.isActive) {
                throw new ForbiddenError('This survey is no longer accepting responses');
            }

            // Check date range
            const now = new Date();
            if (survey.startDate && now < survey.startDate) {
                throw new ForbiddenError('This survey has not started yet');
            }
            if (survey.endDate && now > survey.endDate) {
                throw new ForbiddenError('This survey has ended');
            }

            // Validate required questions
            const requiredQuestions = survey.questions.filter((q: SurveyQuestion) => q.isRequired);
            const missingAnswers = requiredQuestions.filter(
                (q: SurveyQuestion) => !validatedData.answers[q.id] || validatedData.answers[q.id] === ""
            );

            if (missingAnswers.length > 0 && validatedData.isComplete) {
                throw new ValidationError(
                    'Please answer all required questions',
                    missingAnswers.map((q: SurveyQuestion) => ({
                        field: q.id,
                        message: 'This question is required',
                    }))
                );
            }

            // Check for existing response (if not anonymous)
            if (!survey.isAnonymous && userId) {
                const existingResponse = await prisma.surveyResponse.findFirst({
                    where: {
                        surveyId: validatedData.surveyId,
                        userId,
                    },
                });

                if (existingResponse) {
                    throw new ForbiddenError('You have already submitted a response to this survey');
                }
            }

            const response = await prisma.surveyResponse.create({
                data: {
                    surveyId: validatedData.surveyId,
                    userId: survey.isAnonymous ? null : userId,
                    answers: validatedData.answers as any,
                    isComplete: validatedData.isComplete,
                    completedAt: validatedData.isComplete ? new Date() : null,
                    ipAddress: metadata?.ipAddress,
                    userAgent: metadata?.userAgent,
                },
            });

            invalidateSurveyCache(validatedData.surveyId);

            if (userId) {
                await auditService.log({
                    action: 'survey:response_submitted' as any,
                    actorId: userId,
                    metadata: {
                        surveyId: validatedData.surveyId,
                        responseId: response.id,
                        isComplete: validatedData.isComplete,
                    },
                });
            }

            logger.info(
                { surveyId: validatedData.surveyId, responseId: response.id, userId },
                '[SURVEY_SERVICE] Survey response submitted'
            );

            return response;
        } catch (error) {
            logger.error({ err: error, data }, '[SURVEY_SERVICE] Failed to submit response');

            if (error instanceof z.ZodError) {
                throw new ValidationError('Invalid response data', error.issues);
            }
            if (error instanceof AppError) throw error;

            throw new InternalServerError('Could not submit survey response.');
        }
    },

    /**
     * Get user's response to a survey
     */
    async getUserResponse(surveyId: string, userId: string) {
        try {
            const response = await prisma.surveyResponse.findFirst({
                where: {
                    surveyId,
                    userId,
                },
            });

            return response;
        } catch (error) {
            logger.error(
                { err: error, surveyId, userId },
                '[SURVEY_SERVICE] Failed to get user response'
            );
            throw new InternalServerError('Could not fetch response.');
        }
    },

    /**
     * Get all responses for a survey
     */
    async getSurveyResponses(
        surveyId: string,
        pagination: { page?: number; limit?: number } = {}
    ) {
        try {
            const { page = 1, limit = 50 } = pagination;
            const skip = (page - 1) * limit;

            const [responses, total] = await prisma.$transaction([
                prisma.surveyResponse.findMany({
                    where: { surveyId },
                    include: {
                        user: {
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
                    skip,
                    take: limit,
                }),
                prisma.surveyResponse.count({ where: { surveyId } }),
            ]);

            return {
                data: responses,
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
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to get responses');
            throw new InternalServerError('Could not fetch responses.');
        }
    },

    // ========================================================================
    // ANALYTICS
    // ========================================================================

    /**
     * Get survey analytics
     */
    async getSurveyAnalytics(surveyId: string): Promise<SurveyAnalytics> {
        try {
            const cacheKey = CACHE_KEYS.surveyAnalytics(surveyId);
            const cached = surveyCache.get(cacheKey);

            if (cached) return cached;

            const [survey, responses] = await Promise.all([
                this.getSurveyById(surveyId, true),
                prisma.surveyResponse.findMany({
                    where: { surveyId },
                    select: {
                        answers: true,
                        isComplete: true,
                        completedAt: true,
                        createdAt: true,
                        timeSpent: true,
                    },
                }),
            ]);

            const totalResponses = responses.length;
            const completedResponses = responses.filter(r => r.isComplete).length;
            const completionRate = totalResponses > 0 ? (completedResponses / totalResponses) * 100 : 0;

            // Calculate average completion time
            const completionTimes = responses
                .filter(r => r.timeSpent)
                .map(r => r.timeSpent as number);
            const averageCompletionTime =
                completionTimes.length > 0
                    ? completionTimes.reduce((a, b) => a + b, 0) / completionTimes.length
                    : 0;

            // Responses by date
            const responsesByDate = responses.reduce((acc, response) => {
                const date = response.createdAt.toISOString().split('T')[0];
                acc[date] = (acc[date] || 0) + 1;
                return acc;
            }, {} as Record<string, number>);

            // Question analytics
            const questionAnalytics = survey.questions.map((question: SurveyQuestion) => {
                const questionResponses = responses.filter(r => {
                    const answers = r.answers as Record<string, any>;
                    return answers[question.id] !== undefined && answers[question.id] !== null;
                });

                const answers = questionResponses.map(r => {
                    const responseAnswers = r.answers as Record<string, any>;
                    return responseAnswers[question.id];
                });

                // Aggregate answers based on question type
                let aggregatedAnswers: any = {};

                if (question.type === 'radio' || question.type === 'checkbox') {
                    aggregatedAnswers = answers.reduce((acc, answer) => {
                        if (Array.isArray(answer)) {
                            answer.forEach(a => {
                                acc[a] = (acc[a] || 0) + 1;
                            });
                        } else {
                            acc[answer] = (acc[answer] || 0) + 1;
                        }
                        return acc;
                    }, {} as Record<string, number>);
                } else if (question.type === 'rating' || question.type === 'scale') {
                    const numericAnswers = answers.filter(a => typeof a === 'number');
                    aggregatedAnswers = {
                        average: numericAnswers.length > 0
                            ? numericAnswers.reduce((a, b) => a + b, 0) / numericAnswers.length
                            : 0,
                        min: numericAnswers.length > 0 ? Math.min(...numericAnswers) : 0,
                        max: numericAnswers.length > 0 ? Math.max(...numericAnswers) : 0,
                        distribution: numericAnswers.reduce((acc, val) => {
                            acc[val] = (acc[val] || 0) + 1;
                            return acc;
                        }, {} as Record<number, number>),
                    };
                } else {
                    aggregatedAnswers = {
                        responses: answers,
                    };
                }

                return {
                    questionId: question.id,
                    question: question.question,
                    responses: questionResponses.length,
                    answers: aggregatedAnswers,
                };
            });

            const analytics: SurveyAnalytics = {
                totalResponses,
                completedResponses,
                averageCompletionTime,
                completionRate,
                responsesByDate: Object.entries(responsesByDate).map(([date, count]) => ({
                    date,
                    count,
                })),
                questionAnalytics,
            };

            surveyCache.set(cacheKey, analytics, { ttl: 1000 * 60 * 5 }); // 5 minutes cache

            return analytics;
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to get analytics');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not fetch survey analytics.');
        }
    },

    // ========================================================================
    // UTILITY METHODS
    // ========================================================================

    /**
     * Delete survey and all responses
     */
    async deleteSurvey(surveyId: string, actorId: string) {
        try {
            const survey = await prisma.survey.findUnique({
                where: { id: surveyId },
                include: {
                    _count: {
                        select: { responses: true },
                    },
                },
            });

            if (!survey) {
                throw new NotFoundError('Survey');
            }

            await prisma.survey.delete({
                where: { id: surveyId },
            });

            invalidateSurveyCache(surveyId);

            await auditService.log({
                action: 'survey:deleted' as any,
                actorId,
                metadata: {
                    surveyId,
                    responsesDeleted: survey._count.responses,
                },
            });

            logger.info({ surveyId, actorId }, '[SURVEY_SERVICE] Survey deleted');
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to delete survey');
            if (error instanceof AppError) throw error;
            throw new InternalServerError('Could not delete survey.');
        }
    },

    /**
     * Export survey responses to CSV
     */
    async exportResponses(surveyId: string) {
        try {
            const [survey, responses] = await Promise.all([
                this.getSurveyById(surveyId, true),
                prisma.surveyResponse.findMany({
                    where: { surveyId },
                    include: {
                        user: {
                            select: {
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
                }),
            ]);

            // Build CSV headers
            const headers = ['Response ID', 'User Email', 'User Name', 'Completed', 'Submitted At'];
            survey.questions.forEach((q: SurveyQuestion) => {
                const questionText = (q.question as any)["en"] || "Question";
                headers.push(questionText);
            });

            // Build CSV rows
            const rows = responses.map(response => {
                const row = [
                    response.id,
                    response.user?.email || 'Anonymous',
                    response.user?.profile
                        ? `${response.user.profile.firstName} ${response.user.profile.lastName}`
                        : 'Anonymous',
                    response.isComplete ? 'Yes' : 'No',
                    response.createdAt.toISOString(),
                ];

                const answers = response.answers as Record<string, any>;
                survey.questions.forEach((q: SurveyQuestion) => {
                    const answer = (response.answers as Record<string, any>)[q.id];
                    if (Array.isArray(answer)) {
                        row.push(answer.join(", "));
                    } else if (typeof answer === "object") {
                        row.push(JSON.stringify(answer));
                    } else {
                        row.push(String(answer || ""));
                    }
                });

                return row;
            });

            // Convert to CSV string
            const csvContent = [
                headers.join(','),
                ...rows.map(row => row.map(cell => `"${cell}"`).join(',')),
            ].join('\n');

            return {
                content: csvContent,
                filename: `survey-${surveyId}-responses-${new Date().toISOString().split('T')[0]}.csv`,
            };
        } catch (error) {
            logger.error({ err: error, surveyId }, '[SURVEY_SERVICE] Failed to export responses');
            throw new InternalServerError('Could not export responses.');
        }
    },
};