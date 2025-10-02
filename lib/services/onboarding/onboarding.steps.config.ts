// lib/services/onboarding/onboarding.steps.config.ts

import type { OnboardingStepConfig } from './onboarding.types';

// This is the master configuration file of ALL possible steps.
// The `id` property is a placeholder; the service engine assigns the correct sequence ID.
export const ONBOARDING_STEPS_CONFIG: Omit<OnboardingStepConfig, 'id'>[] = [
    {
        name: 'welcome',
        titleKey: 'onboarding.steps.welcome.title',
        descriptionKey: 'onboarding.steps.welcome.description',
        component: 'OnboardingWelcome',
        required: true,
    },
    {
        name: 'roleSelection',
        titleKey: 'onboarding.steps.roleSelection.title',
        descriptionKey: 'onboarding.steps.roleSelection.description',
        component: 'OnboardingRoleSelection',
        required: true,
    },
    {
        name: 'profile',
        titleKey: 'onboarding.steps.profile.title',
        descriptionKey: 'onboarding.steps.profile.description',
        component: 'OnboardingProfile',
        required: false,
    },
    {
        name: 'volunteerDetails',
        titleKey: 'onboarding.steps.volunteerDetails.title',
        descriptionKey: 'onboarding.steps.volunteerDetails.description',
        component: 'OnboardingVolunteerDetails',
        required: true,
    },
    {
        name: 'corporateDetails',
        titleKey: 'onboarding.steps.corporateDetails.title',
        descriptionKey: 'onboarding.steps.corporateDetails.description',
        component: 'OnboardingCorporateDetails',
        required: true,
    },
    {
        name: 'institutionalDetails',
        titleKey: 'onboarding.steps.institutionalDetails.title',
        descriptionKey: 'onboarding.steps.institutionalDetails.description',
        component: 'OnboardingInstitutionalDetails',
        required: true,
    },
    {
        name: 'preferences',
        titleKey: 'onboarding.steps.preferences.title',
        descriptionKey: 'onboarding.steps.preferences.description',
        component: 'OnboardingPreferences',
        required: false,
    },
    {
        name: 'privacy',
        titleKey: 'onboarding.steps.privacy.title',
        descriptionKey: 'onboarding.steps.privacy.description',
        component: 'OnboardingPrivacy',
        required: true,
    },
    {
        name: 'finished',
        titleKey: 'onboarding.steps.finished.title',
        descriptionKey: 'onboarding.steps.finished.description',
        component: 'OnboardingFinished',
        required: true,
    },
];