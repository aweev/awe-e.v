// app/api/v1/surveys/route.ts
// import { createApiHandler } from '@/lib/api-handler';
// import { surveyService } from '@/lib/services/survey/survey.service';
// import { PERMISSIONS } from '@/lib/audit/actions';
// import { NextResponse } from 'next/server';
// import { z } from 'zod';

// const createSurveySchema = z.object({
//     title: z.record(z.string()),
//     description: z.record(z.string()).optional(),
//     type: z.string().default('feedback'),
//     isActive: z.boolean().default(true),
//     isAnonymous: z.boolean().default(false),
//     targetAudience: z.array(z.string()).optional(),
//     programId: z.string().optional(),
//     startDate: z.coerce.date().optional(),
//     endDate: z.coerce.date().optional(),
//     questions: z.array(z.object({
//         question: z.record(z.string()),
//         type: z.enum(['text', 'textarea', 'radio', 'checkbox', 'rating', 'scale']),
//         options: z.record(z.array(z.string())).optional(),
//         isRequired: z.boolean().default(false),
//         order: z.number().optional(),
//         showIf: z.any().optional(),
//     })).min(1),
// });

// const listSurveysQuerySchema = z.object({
//     type: z.string().optional(),
//     isActive: z.coerce.boolean().