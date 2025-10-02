// stores/onboardingStore.ts
import { create } from 'zustand';
import type { OnboardingProgress } from '@/lib/onboarding/onboarding.types';

interface OnboardingState {
  progress: OnboardingProgress | null;
  isLoading: boolean;
  
  // Actions
  setProgress: (progress: OnboardingProgress | null) => void;
  setIsLoading: (isLoading: boolean) => void;
  reset: () => void;
}

const initialState = {
  progress: null,
  isLoading: true,
};

export const useOnboardingStore = create<OnboardingState>((set) => ({
  ...initialState,
  setProgress: (progress) => set({ progress, isLoading: false }),
  setIsLoading: (isLoading) => set({ isLoading }),
  reset: () => set(initialState),
}));