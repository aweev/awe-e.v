// lib/services/onboarding/onboarding.paths.ts

import { Role } from "@prisma/client";
import { OnboardingStepName } from "./onboarding.types";

export const DEFAULT_ONBOARDING_PATH: OnboardingStepName[] = [
    'welcome',
    'roleSelection',
];

export const ONBOARDING_PATHS: Record<Role, OnboardingStepName[]> = {
    // Admin Roles (simplified path)
    SUPER_ADMIN: ['welcome', 'roleSelection', 'profile', 'finished'],
    EXECUTIVE_DIRECTOR: ['welcome', 'roleSelection', 'profile', 'finished'],
    PROGRAM_MANAGER: ['welcome', 'roleSelection', 'profile', 'finished'],
    CONTENT_MANAGER: ['welcome', 'roleSelection', 'profile', 'finished'],
    FINANCE_MANAGER: ['welcome', 'roleSelection', 'profile', 'finished'],
    VOLUNTEER_COORDINATOR: ['welcome', 'roleSelection', 'profile', 'finished'],
    BOARD_MEMBER: ['welcome', 'roleSelection', 'profile', 'finished'],
    DATA_ANALYST: ['welcome', 'roleSelection', 'profile', 'finished'],

    // Member & Partner Roles (detailed paths)
    ACTIVE_VOLUNTEER: [
        'welcome', 'roleSelection', 'profile', 'volunteerDetails', 'preferences', 'privacy', 'finished',
    ],
    PROGRAM_MENTOR: [
        'welcome', 'roleSelection', 'profile', 'volunteerDetails', 'preferences', 'finished',
    ],
    CORPORATE_PARTNER: [
        'welcome', 'roleSelection', 'profile', 'corporateDetails', 'preferences', 'privacy', 'finished',
    ],
    INSTITUTIONAL_PARTNER: [
        'welcome', 'roleSelection', 'profile', 'institutionalDetails', 'preferences', 'privacy', 'finished',
    ],
    PROGRAM_ALUMNI: [
        'welcome', 'roleSelection', 'profile', 'preferences', 'privacy', 'finished',
    ],
    INDIVIDUAL_MAJOR_DONOR: [
        'welcome', 'roleSelection', 'profile', 'preferences', 'privacy', 'finished',
    ],
};