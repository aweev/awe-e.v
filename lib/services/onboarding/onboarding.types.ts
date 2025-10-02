import type { Role, UserOnboarding } from '@prisma/client';
export type { UserOnboarding };

export type OnboardingStepName =
  | 'welcome'
  | 'roleSelection'
  | 'profile'
  | 'volunteerDetails'
  | 'corporateDetails'
  | 'institutionalDetails'
  | 'preferences'
  | 'privacy'
  | 'finished';

export interface UpdateOnboardingInput {
  userId: string;
  currentStep?: number;
  completedSteps?: number[];
  stepData?: Record<string, unknown>;
  isCompleted?: boolean;
}

export interface OnboardingStep {
  id: number;
  name: OnboardingStepName;
  titleKey: string | Record<Role, string>;
  descriptionKey: string | Record<Role, string>;
  component: string;
  required: boolean;
  completed: boolean;
  data?: Record<string, unknown>;
}

export interface OnboardingProgress {
  currentStep: number;
  completedSteps: number[];
  totalSteps: number;
  isCompleted: boolean;
  steps: OnboardingStep[];
}
export interface UpdateOnboardingInput {
  userId: string;
  currentStep?: number;
  completedSteps?: number[];
  stepData?: Record<string, unknown>;
  isCompleted?: boolean;
}

export interface OnboardingStepConfig {
  name: OnboardingStepName;
  titleKey: string | Record<Role, string>;
  descriptionKey: string | Record<Role, string>;
  component: string;
  required: boolean;
}