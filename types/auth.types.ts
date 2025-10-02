// types/auth.types.ts
import { Role, UserProfile } from "@prisma/client";
import { PermissionString } from "@/lib/audit/actions";

export interface AuthUser {
    id: string;
    email: string;
    username?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    memberType?: string | null;
    roles: Role[];
    profile: UserProfile;
    mfaEnabled: boolean;
    onboardingCompleted: boolean;
    permissions: PermissionString[];
}

export interface AuthResponse {
    user: AuthUser;
    accessToken: string;
    onboardingCompleted: boolean;
}

export interface LoginResponse extends Partial<AuthResponse> {
    mfaRequired?: boolean;
    mfaToken?: string;

    deviceVerificationRequired?: boolean;
    deviceId?: string;

    user?: AuthUser;
    accessToken?: string;
}

export interface RegisterResponse {
    requiresVerification: boolean;
    message: string;
}

export interface AccessTokenPayload {
    sub: string;
    email?: string;
    roles: Role[];
    permissions: PermissionString[];

    // Impersonation data
    actAsSub?: string;
    isImpersonating: boolean;

    iat?: number;
    exp?: number;
    iss?: string;
    aud?: string;
}

export interface RefreshTokenPayload {
    sub: string;
    jti: string;
    type: "refresh";

    iat?: number;
    exp?: number;
    iss?: string;
    aud?: string;
}

export interface AuthTokens {
    accessToken: string;
    refreshToken: string;
}

export interface DeviceInfo {
    id: string;
    name: string;
    type: string;
    lastUsed: Date;
    trusted: boolean;
    current: boolean;
}

export interface MfaVerificationRequest {
    code: string;
    mfaToken: string;
}

export interface DeviceVerificationRequest {
    deviceId: string;
    verificationCode?: string;
}

export interface OAuthCallbackResponse extends Partial<AuthResponse> {

    deviceVerificationRequired?: boolean;
    deviceId?: string;

    user?: AuthUser;
    accessToken?: string;
}

export interface PasswordChangeRequest {
    currentPassword: string;
    newPassword: string;
    confirmPassword: string;
}

export interface PasswordResetRequest {
    token: string;
    newPassword: string;
    confirmPassword: string;
}

export interface LoginCredentials {
    email: string;
    password: string;
    rememberMe?: boolean;
}

export interface RegistrationData {
    email: string;
    password: string;
    confirmPassword: string;
    firstName?: string;
    lastName?: string;
}

export type OAuthProvider = 'google' | 'facebook' | 'github';

export interface OAuthLoginRequest {
    code: string;
    redirectUri: string;
    provider: OAuthProvider;
}

export interface SessionInfo {
    user: AuthUser;
    isAuthenticated: boolean;
    expiresAt: Date;
    deviceInfo?: DeviceInfo;
}

export interface AuthContextValue {
    user: AuthUser | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    login: (email: string, password: string, rememberMe?: boolean) => Promise<boolean>;
    logout: () => Promise<void>;
    register: (data: RegistrationData) => Promise<boolean>;
    refreshSession: () => Promise<void>;
}

export interface PermissionCheck {
    hasPermission: boolean;
    reason?: string;
}

export interface RoleCheck {
    hasRole: boolean;
    reason?: string;
}
