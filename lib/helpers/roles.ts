// lib/auth/role.ts
import { Role, UserSession } from "@prisma/client";
import type { IconName } from "@/components/ui/icon";

export type RoleInfo = {
  value: Role;
  labelKey: string;
  descriptionKey: string;
  icon: IconName;
};

export const ONBOARDING_ROLES: RoleInfo[] = [
  {
    value: Role.ACTIVE_VOLUNTEER,
    labelKey: "Onboarding.roles.active_volunteer.label",
    descriptionKey: "Onboarding.roles.active_volunteer.description",
    icon: "heartHandshake",
  },
  {
    value: Role.PROGRAM_MENTOR,
    labelKey: "Onboarding.roles.program_mentor.label",
    descriptionKey: "Onboarding.roles.program_mentor.description",
    icon: "graduationCap",
  },
  {
    value: Role.PROGRAM_ALUMNI,
    labelKey: "Onboarding.roles.program_alumni.label",
    descriptionKey: "Onboarding.roles.program_alumni.description",
    icon: "users",
  },
  {
    value: Role.CORPORATE_PARTNER,
    labelKey: "Onboarding.roles.corporate_partner.label",
    descriptionKey: "Onboarding.roles.corporate_partner.description",
    icon: "building",
  },
  {
    value: Role.INSTITUTIONAL_PARTNER,
    labelKey: "Onboarding.roles.institutional_partner.label",
    descriptionKey: "Onboarding.roles.institutional_partner.description",
    icon: "landmark",
  },
  {
    value: Role.INDIVIDUAL_MAJOR_DONOR,
    labelKey: "Onboarding.roles.individual_major_donor.label",
    descriptionKey: "Onboarding.roles.individual_major_donor.description",
    icon: "gift",
  },
];

export const ADMIN_ROLES = [
  Role.SUPER_ADMIN,
  Role.EXECUTIVE_DIRECTOR,
  Role.PROGRAM_MANAGER,
  Role.CONTENT_MANAGER,
  Role.FINANCE_MANAGER,
  Role.VOLUNTEER_COORDINATOR,
  Role.BOARD_MEMBER,
  Role.DATA_ANALYST,
] as const;

export const MEMBER_ROLES = [
  Role.ACTIVE_VOLUNTEER,
  Role.PROGRAM_ALUMNI,
  Role.CORPORATE_PARTNER,
  Role.INDIVIDUAL_MAJOR_DONOR,
  Role.INSTITUTIONAL_PARTNER,
  Role.PROGRAM_MENTOR,
] as const;

export const ALL_ROLES = [...ADMIN_ROLES, ...MEMBER_ROLES] as const;

export type AdminRole = typeof ADMIN_ROLES[number];
export type MemberRole = typeof MEMBER_ROLES[number];
export type UserRole = AdminRole | MemberRole;

export interface User {
  id: string;
  email: string;
  roles: UserRole[];
  locale: 'en' | 'de' | 'fr';
  created_at: string;
  updated_at: string;
  profile?: UserProfile;
}

export interface UserProfile {
  id: string;
  user_id: string;
  first_name: string;
  last_name: string;
  avatar_url?: string;
  bio?: string;
  phone?: string;
  organization?: string;
  position?: string;
  preferences: UserPreferences;
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'system';
  language: 'en' | 'de' | 'fr';
  notifications: {
    email: boolean;
    push: boolean;
    sms: boolean;
    marketing: boolean;
  };
  accessibility: {
    high_contrast: boolean;
    reduced_motion: boolean;
    screen_reader: boolean;
  };
}

export interface AuthSession {
  user: User;
  session: UserSession;
  permissions: string[];
}

export interface Permission {
  resource: string;
  action: 'create' | 'read' | 'update' | 'delete' | 'manage';
}

// Route protection types
export type RouteType = 'admin' | 'members' | 'public';
export type LocaleType = 'en' | 'de' | 'fr';

export interface RouteConfig {
  type: RouteType;
  supportedLocales: readonly LocaleType[];
  requiresAuth: boolean;
  requiredRoles?: readonly UserRole[];
}

// Notification types
export const NOTIFICATION_CHANNELS = {
  general: "General",
  community: "Community",
  billing: "Billing",
} as const;

export type NotificationChannel = keyof typeof NOTIFICATION_CHANNELS;

export interface Notification {
  id: string;
  user_id: string;
  created_at: string;
  type: "info" | "success" | "warning" | "critical";
  channel?: NotificationChannel;
  title: string;
  message?: string;
  read: boolean;
  link_href?: string;
}

export interface NotificationPayload extends Notification {
  actions?: {
    label: string;
    onClick: () => void;
  }[];
  sound?: boolean;
}