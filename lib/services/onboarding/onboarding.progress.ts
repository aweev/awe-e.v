import type { OnboardingStep, OnboardingProgress } from './onboarding.types';

export const DEFAULT_TOTAL_STEPS = 5;

export function buildProgress(steps: OnboardingStep[]): OnboardingProgress {
  const currentStepIndex = steps.findIndex(step => !step.completed);
  const currentStep = currentStepIndex === -1 ? steps.length - 1 : currentStepIndex;

  const completedSteps = steps
    .filter((s) => s.completed)
    .map((s) => s.id);

  const isCompleted = steps
    .filter(s => s.required)
    .every(s => s.completed);

  return {
    currentStep,
    completedSteps,
    totalSteps: steps.length,
    isCompleted,
    steps,
  };
}

export function completionPercentage(progress: OnboardingProgress): number {
  const requiredSteps = progress.steps.filter((s) => s.required);
  if (requiredSteps.length === 0) {
    return 100;
  }

  const completedRequiredSteps = requiredSteps.filter((s) => s.completed).length;
  return Math.round((completedRequiredSteps / requiredSteps.length) * 100);
}

export function nextStep(steps: OnboardingStep[], from = 0): number | null {
  for (let i = from + 1; i < steps.length; i++) {
    if (!steps[i].completed) return i;
  }
  return null;
}

export function prevStep(steps: OnboardingStep[], from: number): number | null {
  for (let i = from - 1; i >= 0; i--) {
    return i; // Return the previous step index
  }
  return null;
}