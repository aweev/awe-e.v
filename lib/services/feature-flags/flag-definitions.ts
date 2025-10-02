import { Role } from '@prisma/client';

export interface FlagEvaluationContext {
    userId?: string;
    roles?: Role[];
}

export const flagDefinitions = {
    'dynamic-onboarding': {
        description: 'Controls the new database-driven onboarding flow.',
        defaultValue: false,
    },
    'new-dashboard-layout': {
        description: 'Toggles the redesigned member dashboard.',
        defaultValue: false,
    },
    'ai-assistant-enabled': {
        description: 'Enables the experimental AI assistant feature.',
        defaultValue: false,
    },
} as const;

export type FeatureFlagKey = keyof typeof flagDefinitions;