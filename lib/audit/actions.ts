// lib/audit/actions.ts (Updated)
export const PERMISSIONS = {
    // --- System & Wildcards ---
    ALL_MANAGE: 'all:manage',

    // --- Admin Panel Access ---
    ADMIN_PANEL_ACCESS: 'admin_panel:access',

    // --- User & Role Management ---
    USERS_CREATE: 'users:create',
    USERS_READ: 'users:read',
    USERS_UPDATE: 'users:update',
    USERS_DELETE: 'users:delete',
    USERS_IMPERSONATE: 'users:impersonate',
    USERS_MANAGE: 'users:manage',
    ROLES_READ: 'roles:read',
    ROLES_ASSIGN: 'roles:assign',
    ROLES_MANAGE: 'roles:manage',

    // --- CMS: Pages & Blocks ---
    PAGES_CREATE: 'pages:create',
    PAGES_READ: 'pages:read',
    PAGES_UPDATE: 'pages:update',
    PAGES_DELETE: 'pages:delete',
    PAGES_PUBLISH: 'pages:publish',
    PAGES_MANAGE: 'pages:manage',
    BLOCKS_CREATE: 'blocks:create',
    BLOCKS_READ: 'blocks:read',
    BLOCKS_UPDATE: 'blocks:update',
    BLOCKS_DELETE: 'blocks:delete',
    BLOCKS_REORDER: 'blocks:reorder',
    BLOCKS_MANAGE: 'blocks:manage',

    // --- Program Management ---
    PROGRAMS_CREATE: 'programs:create',
    PROGRAMS_READ: 'programs:read',
    PROGRAMS_UPDATE: 'programs:update',
    PROGRAMS_DELETE: 'programs:delete',
    PROGRAMS_MANAGE: 'programs:manage',
    PROGRAM_CATEGORIES_MANAGE: 'program_categories:manage',

    // --- Event Management ---
    EVENTS_CREATE: 'events:create',
    EVENTS_READ: 'events:read',
    EVENTS_UPDATE: 'events:update',
    EVENTS_DELETE: 'events:delete',
    EVENTS_MANAGE: 'events:manage',
    EVENTS_VIEW_ATTENDEES: 'events:view_attendees',

    // --- Volunteer Management ---
    VOLUNTEERS_READ: 'volunteers:read',
    VOLUNTEERS_MANAGE: 'volunteers:manage',
    VOLUNTEER_OPPORTUNITIES_MANAGE: 'volunteer_opportunities:manage',

    // --- Financial Management ---
    FINANCES_READ: 'finances:read',
    FINANCES_MANAGE: 'finances:manage',
    DONATIONS_READ: 'donations:read',
    DONATIONS_MANAGE: 'donations:manage',
    GRANTS_READ: 'grants:read',
    GRANTS_MANAGE: 'grants:manage',

    // --- Analytics & Reporting ---
    ANALYTICS_READ: 'analytics:read',
    REPORTS_READ: 'reports:read',
    REPORTS_MANAGE: 'reports:manage',
    AUDIT_LOGS_READ: 'audit_logs:read',

    // --- Feature-flags ---
    FEATURE_FLAGS_UPDATE: 'feature_flags:update',

    // --- System Settings ---
    SETTINGS_READ: 'settings:read',
    SETTINGS_UPDATE: 'settings:update',

    // --- Device Management ---
    DEVICES_READ: 'devices:read',
    DEVICES_TRUST: 'devices:trust',
    DEVICES_REVOKE: 'devices:revoke',

} as const;

// This creates a TypeScript type that is a union of all the values in the PERMISSIONS object.
// e.g., 'all:manage' | 'admin_panel:access' | 'users:create' | ...
export type PermissionString = typeof PERMISSIONS[keyof typeof PERMISSIONS];

export const AUDIT_ACTIONS = {
    // --- Auth & Security ---
    LOGIN_SUCCESS: 'auth:login_success',
    LOGIN_FAILED: 'auth:login_failed',
    LOGIN_MFA_REQUIRED: 'auth:login_mfa_required',
    LOGIN_MFA_FAILED: 'auth:login_mfa_failed',
    LOGOUT_SUCCESS: 'auth:logout_success',
    SIGNUP_SUCCESS: 'auth:signup_success',
    EMAIL_VERIFIED: 'auth:email_verified',
    PASSWORD_RESET_SUCCESS: 'auth:password_reset_success',
    PASSWORD_CHANGED: 'auth:password_changed',
    PASSWORD_RESET_REQUESTED: 'auth:password_reset_requested',
    REFRESH_TOKEN_REUSE_OR_INVALID: 'auth:refresh_token_reuse_or_invalid',
    ACCOUNT_LOCKED: 'auth:account_locked',

    // --- User Management ---
    USER_PROFILE_UPDATED: 'user:profile_updated',
    USER_PREFERENCES_UPDATED: 'user:preferences_updated',
    USER_AVATAR_UPDATED: 'user:avatar_updated',
    USER_DEACTIVATED: 'user:deactivated',
    USER_REACTIVATED: 'user:reactivated',
    USER_SKILL_ADDED: 'user:skill_added',
    USER_SKILL_UPDATED: 'user:skill_updated',
    USER_SKILL_REMOVED: 'user:skill_removed',
    USER_ROLE_ASSIGNED: 'user:role_assigned',
    USER_ROLE_REMOVED: 'user:role_removed',

    // --- Device Management ---
    NEW_DEVICE_DETECTED: 'device:new_detected',
    DEVICE_TRUSTED: 'device:trusted',
    DEVICE_REVOKED: 'device:revoked',

    // --- Events ---
    EVENT_CREATED: 'event_created',
    EVENT_UPDATED: 'event_updated',
    EVENT_DELETED: 'event_deleted',
    EVENT_REGISTRATION_SUCCESS: 'event_registration_success',
    EVENT_REGISTRATION_WAITLISTED: 'event_registration_waitlisted',
    EVENT_UNREGISTERED: 'event_unregistered',
    EVENT_ATTENDEES_VIEWED: 'event_attendees_viewed',

    // --- API & System ---
    API_RATE_LIMIT_EXCEEDED: 'api:rate_limit_exceeded',
    API_FORBIDDEN_ERROR: 'api:forbidden_error',

    // Session Management
    SESSION_LIMIT_EXCEEDED: 'auth:session_limit_exceeded',
    SESSION_FINGERPRINT_MISMATCH: 'auth:session_fingerprint_mismatch',
    CONCURRENT_SESSION_DETECTED: 'auth:concurrent_session_detected',

    // Consent
    CONSENT_GRANTED: 'user:consent_granted',
    CONSENT_WITHDRAWN: 'user:consent_withdrawn',
    CONSENT_UPDATED: 'user:consent_updated',

    // Password
    PASSWORD_EXPIRY_WARNING: 'auth:password_expiry_warning',
    WEAK_PASSWORD_DETECTED: 'auth:weak_password_detected',

    // Device
    DEVICE_LIMIT_EXCEEDED: 'device:limit_exceeded',
    SUSPICIOUS_DEVICE_DETECTED: 'device:suspicious_detected',
} as const;

export type AuditActionString = typeof AUDIT_ACTIONS[keyof typeof AUDIT_ACTIONS];