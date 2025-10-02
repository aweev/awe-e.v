then we will do this 
'''
Auth & User Services:
Implement User model, registration, login (password-based first), and session management (UserSession).
Implement basic RBAC logic (User roles field, Permission model). Create a Super Admin role.
Build the basic Admin Panel UI for user management (view users, assign roles).
'''

before this this 
'''
Feature Flag Service:
Implement the FeatureFlag model and a simple service/hook (useFeatureFlag('flag_key')).
Reasoning: Every single feature from this point on should be wrapped in a feature flag. This is your most powerful tool for avoiding deployment bottlenecks and enabling gradual rollouts.
'''

please check if auth service is production ready.
'''
// lib/services/auth/account-locking.service.ts
import { prisma } from '@/lib/db';
import { add, sub } from 'date-fns';
import { auditService } from '@/lib/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';

export interface AccountLockingConfig {
    maxAttempts: number;
    lockoutDurationMinutes: number;
    resetAfterMinutes?: number;
}

const DEFAULT_CONFIG: AccountLockingConfig = {
    maxAttempts: 5,
    lockoutDurationMinutes: 15,
    resetAfterMinutes: 60,
};

export class AccountLockedError extends Error {
    constructor(
        public lockedUntil: Date,
        message = 'Account has been temporarily locked due to too many failed login attempts. Please try again later.'
    ) {
        super(message);
        this.name = 'AccountLockedError';
    }
}

export const accountLockingService = {
    async getConfig(): Promise<AccountLockingConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    async recordFailedAttempt(email: string): Promise<{ isLocked: boolean; lockedUntil?: Date }> {
        const config = await this.getConfig();
        const now = new Date();

        // Cutoff = attempts considered only within the resetAfterMinutes window
        const cutoffTime = sub(now, { minutes: config.resetAfterMinutes || 60 });

        // Record new failed attempt
        await prisma.failedLoginAttempt.create({
            data: { email }
        });

        // Count recent attempts (within cutoff)
        const attemptsCount = await prisma.failedLoginAttempt.count({
            where: {
                email,
                createdAt: { gte: cutoffTime }
            }
        });

        // Check if account should be locked
        if (attemptsCount >= config.maxAttempts) {
            const lockedUntil = add(now, { minutes: config.lockoutDurationMinutes });

            // Update user lock info
            await prisma.user.updateMany({
                where: { email },
                data: { lockedUntil }
            });

            await auditService.log({
                action: AUDIT_ACTIONS.ACCOUNT_LOCKED,
                metadata: { email, attemptsCount, lockedUntil }
            });

            return { isLocked: true, lockedUntil };
        }

        return { isLocked: false };
    },

    async resetFailedAttempts(email: string): Promise<void> {
        await prisma.failedLoginAttempt.deleteMany({ where: { email } });
        await prisma.user.updateMany({
            where: { email },
            data: { lockedUntil: null }
        });
    },

    async isAccountLocked(email: string): Promise<{ isLocked: boolean; lockedUntil?: Date }> {
        const user = await prisma.user.findUnique({
            where: { email },
            select: { lockedUntil: true }
        });

        if (!user) return { isLocked: false };

        const now = new Date();
        if (user.lockedUntil && user.lockedUntil > now) {
            return { isLocked: true, lockedUntil: user.lockedUntil };
        }

        // If lock has expired, reset lock info
        if (user.lockedUntil && user.lockedUntil <= now) {
            await this.resetFailedAttempts(email);
        }

        return { isLocked: false };
    }
};

'''
'''
// lib/auth/auth.service.ts (Updated)
import { prisma } from "@/lib/db";
import { InvalidPasswordResetTokenError, passwordService } from "./password.service";
import { signAccessToken, signMfaToken, signRefreshToken, verifyRefreshToken } from "./jwt.service";
import { sessionService } from "./session.service";
import { verifyTotpToken } from "./totp.service";
import { AccountExistsUnverifiedError, AccountExistsVerifiedError, AuthError, InvalidCredentialsError, InvalidTokenError } from "../../errors/auth.errors";
import type { AuthResponse, AuthUser, AccessTokenPayload } from "@/types/auth.types";
import { Prisma, User, UserProfile, UserOnboarding, TokenType } from "@prisma/client";
import { rbacService } from "./rbac.service";
import { inngest } from "@/inngest/client";
import { onboardingService } from "@/lib/services/onboarding/onboarding.service";
import type { Locale } from "@/lib/i18n";
import { signUpSchema } from "../../schemas/auth.schemas";
import z from "zod";
import { auditService } from "@/lib/services/audit.service";
import { hashTokenForDb } from "../../utils/auth.utils";
import type { PermissionString } from "@/lib/audit/actions";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";
import { featureFlagService } from "@/lib/services/feature-flags/feature-flag.service";
import { consumeLogin } from "@/lib/services/rate-limit";
import { accountLockingService, AccountLockedError } from "./account-locking.service";
import { passwordPolicyService, PasswordPolicyError } from "./password-policy.service";
import { deviceManagementService, DeviceInfo, NewDeviceError } from "./device-management.service";

type SignUpCredentials = z.infer<typeof signUpSchema>;
type UserWithRelations = User & {
  profile: UserProfile | null;
  onboarding: UserOnboarding | null;
};


function assertUserHasAllRelations(user: UserWithRelations): asserts user is User & { profile: UserProfile; onboarding: UserOnboarding } {
  if (!user.profile) {
    throw new Error(`Critical Error: User ${user.id} is missing a profile and cannot be authenticated.`);
  }
  if (!user.onboarding) {
    throw new Error(`Critical Error: User ${user.id} is missing an onboarding record.`);
  }
}

export type LoginFinalizationResult = {
  authResponse: AuthResponse;
  refreshToken: string;
  deviceInfo?: {
    isNewDevice: boolean;
    deviceId: string;
    requiresVerification?: boolean;
  };
};

export async function finalizeLogin(
  user: UserWithRelations,
  ip?: string,
  userAgent?: string,
  deviceInfo?: DeviceInfo
): Promise<LoginFinalizationResult> {
  const permissionsSet = await rbacService.getPermissionsForRoles(user.roles);
  const permissions = Array.from(permissionsSet) as PermissionString[];

  const session = await sessionService.create(user.id, ip, userAgent);

  const onboarding = await onboardingService.getOrCreate(user.id);

  const isOnboardingEnabled = await featureFlagService.isEnabled('dynamic-onboarding', {
    userId: user.id,
    roles: user.roles,
  });

  const needsOnboarding = isOnboardingEnabled && !onboarding.isCompleted;

  const accessTokenPayload: AccessTokenPayload = {
    sub: user.id,
    email: user.email,
    roles: user.roles,
    permissions,
    isImpersonating: false,
  };

  const accessToken = await signAccessToken(accessTokenPayload);
  const refreshToken = await signRefreshToken({ sub: user.id, jti: session.id });

  await prisma.user.update({ where: { id: user.id }, data: { lastLoginAt: new Date() } });
  await auditService.log({ action: AUDIT_ACTIONS.LOGIN_SUCCESS, actorId: user.id, ip, userAgent });

  const result: LoginFinalizationResult = {
    authResponse: {
      user: toAuthUser(user, permissions, onboarding.isCompleted),
      accessToken,
      onboardingCompleted: needsOnboarding ? false : true,
    },
    refreshToken,
  };

  // Add device information if available
  if (deviceInfo) {
    const deviceResult = await deviceManagementService.recordDevice(user.id, deviceInfo, false);
    result.deviceInfo = {
      isNewDevice: deviceResult.isNewDevice,
      deviceId: deviceResult.deviceId,
      requiresVerification: deviceResult.requiresVerification
    };
  }

  return result;
}

export function toAuthUser(user: UserWithRelations, permissions: PermissionString[], onboardingCompleted: boolean): AuthUser {
  assertUserHasAllRelations(user);

  return {
    id: user.id,
    email: user.email,
    username: user.username,
    firstName: user.profile.firstName,
    lastName: user.profile.lastName,
    roles: user.roles,
    profile: user.profile,
    mfaEnabled: user.mfaEnabled,
    permissions,
    onboardingCompleted,
  };
}

export const authService = {
  async register(credentials: SignUpCredentials, ip?: string, locale: Locale = 'en'): Promise<User> {
    const { email, password } = credentials;

    // Check rate limiting
    const rateLimitResult = await consumeLogin(email);
    if (!rateLimitResult.allowed) {
      throw new AuthError(`Too many registration attempts. Please try again in ${rateLimitResult.retryAfterSeconds} seconds.`);
    }

    // Validate password policy
    const passwordValidation = await passwordPolicyService.validatePassword(password, { email });
    if (!passwordValidation.isValid) {
      throw new PasswordPolicyError(passwordValidation.issues || []);
    }

    const existingUser = await prisma.user.findUnique({ where: { email } });

    if (existingUser) {
      if (!existingUser.isVerified) {
        await inngest.send({
          name: 'auth/user.registered',
          data: { userId: existingUser.id, locale },
        });
        throw new AccountExistsUnverifiedError();
      } else {
        throw new AccountExistsVerifiedError();
      }
    }

    const hashedPassword = await passwordService.hash(password);
    const initialOnboardingSteps = onboardingService.generateStepsForRole_Dynamic(null);

    const newUser = await prisma.user.create({
      data: {
        email,
        hashedPassword,
        roles: [],
        profile: {
          create: {},
        },
        onboarding: {
          create: {
            steps: initialOnboardingSteps as unknown as Prisma.JsonArray,
          }
        }
      },
    });

    // Save password to history
    await passwordPolicyService.savePasswordToHistory(newUser.id, hashedPassword);

    await inngest.send({
      name: 'auth/user.registered',
      data: { userId: newUser.id, locale },
    });

    await auditService.log({ action: 'signup_success', actorId: newUser.id, ip });
    return newUser;
  },

  async loginWithPassword(
    email: string,
    password: string,
    ip?: string,
    userAgent?: string,
    deviceInfo?: DeviceInfo
  ): Promise<LoginFinalizationResult | { mfaRequired: true; mfaToken: string } | { deviceVerificationRequired: true; deviceId: string }> {
    // Check rate limiting
    const rateLimitResult = await consumeLogin(email);
    if (!rateLimitResult.allowed) {
      await auditService.log({
        action: AUDIT_ACTIONS.LOGIN_FAILED,
        ip,
        metadata: { email, reason: "rate_limit_exceeded" }
      });
      throw new AuthError(`Too many login attempts. Please try again in ${rateLimitResult.retryAfterSeconds} seconds.`);
    }

    // Check if account is locked
    const accountLockStatus = await accountLockingService.isAccountLocked(email);
    if (accountLockStatus.isLocked) {
      await auditService.log({
        action: AUDIT_ACTIONS.LOGIN_FAILED,
        ip,
        metadata: { email, reason: "account_locked", lockedUntil: accountLockStatus.lockedUntil }
      });
      throw new AccountLockedError(accountLockStatus.lockedUntil!);
    }

    const user = await prisma.user.findUnique({
      where: { email },
      include: { profile: true, onboarding: true },
    });

    if (!user || !user.hashedPassword) {
      await accountLockingService.recordFailedAttempt(email);
      await auditService.log({ action: AUDIT_ACTIONS.LOGIN_FAILED, ip, metadata: { email, reason: "account_not_found" } });
      throw new InvalidCredentialsError();
    }

    const isPasswordValid = await passwordService.compare(password, user.hashedPassword);
    if (!isPasswordValid) {
      await accountLockingService.recordFailedAttempt(email);
      await auditService.log({
        action: "login_failed",
        actorId: user.id,
        ip,
        userAgent,
        metadata: { reason: "invalid_password" }
      });
      throw new InvalidCredentialsError();
    }

    if (!user.isVerified) {
      await auditService.log({
        action: "login_failed",
        actorId: user.id,
        ip,
        userAgent,
        metadata: { reason: "email_not_verified" }
      });
      await inngest.send({
        name: 'auth/user.registered',
        data: { userId: user.id, locale: 'en' },
      });
      throw new AuthError("Your account is not verified. We've sent a new verification link to your email.");
    }

    // Reset failed attempts on successful password validation
    await accountLockingService.resetFailedAttempts(email);

    // Check device trust if device info is provided
    if (deviceInfo) {
      const deviceStatus = await deviceManagementService.isTrustedDevice(user.id, deviceInfo);

      if (!deviceStatus.isTrusted) {
        const config = await deviceManagementService.getConfig();
        if (config.requireVerificationForNewDevices) {
          // Record the device but mark it as untrusted
          const deviceResult = await deviceManagementService.recordDevice(user.id, deviceInfo, false);

          return {
            deviceVerificationRequired: true,
            deviceId: deviceResult.deviceId
          };
        }
      }
    }

    if (user.mfaEnabled) {
      const mfaToken = await signMfaToken({ sub: user.id });
      await auditService.log({ action: "login_mfa_required", actorId: user.id, metadata: { ip } });
      return { mfaRequired: true, mfaToken };
    }

    return finalizeLogin(user, ip, userAgent, deviceInfo);
  },

  async verifyMfaAndLogin(
    userId: string,
    code: string,
    ip?: string,
    userAgent?: string,
    deviceInfo?: DeviceInfo
  ): Promise<LoginFinalizationResult> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { profile: true, onboarding: true },
    });

    if (!user?.mfaEnabled || !user.mfaSecret) {
      throw new InvalidCredentialsError("MFA not set up for this user.");
    }

    if (!verifyTotpToken(user.mfaSecret, code)) {
      await auditService.log({ action: "login_mfa_failed", actorId: user.id, ip, userAgent });
      throw new InvalidCredentialsError("Invalid MFA code.");
    }

    return finalizeLogin(user, ip, userAgent, deviceInfo);
  },

  async verifyDeviceAndLogin(
    userId: string,
    deviceId: string,
    ip?: string,
    userAgent?: string,
    deviceInfo?: DeviceInfo
  ): Promise<LoginFinalizationResult> {
    // Verify the device belongs to the user
    const device = await prisma.trustedDevice.findFirst({
      where: {
        id: deviceId,
        userId
      }
    });

    if (!device) {
      throw new AuthError("Invalid device ID.");
    }

    // Trust the device
    await deviceManagementService.trustDevice(userId, deviceId);

    // Get user and complete login
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { profile: true, onboarding: true },
    });

    if (!user) {
      throw new AuthError("User not found.");
    }

    return finalizeLogin(user, ip, userAgent, deviceInfo);
  },

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
    ip?: string,
    userAgent?: string
  ): Promise<void> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { profile: true }
    });

    if (!user || !user.hashedPassword) {
      throw new AuthError("User not found or invalid account state.");
    }

    // Verify current password
    const isCurrentPasswordValid = await passwordService.compare(currentPassword, user.hashedPassword);
    if (!isCurrentPasswordValid) {
      await auditService.log({
        action: "password_change_failed",
        actorId: userId,
        ip,
        userAgent,
        metadata: { reason: "invalid_current_password" }
      });
      throw new AuthError("Current password is incorrect.");
    }

    // Validate new password policy
    const passwordValidation = await passwordPolicyService.validatePassword(
      newPassword,
      {
        email: user.email,
        firstName: user.profile?.firstName || undefined,
        lastName: user.profile?.lastName || undefined,
        username: user.username || undefined
      }
    );

    if (!passwordValidation.isValid) {
      throw new PasswordPolicyError(passwordValidation.issues || []);
    }

    // Check password history
    const passwordHistoryCheck = await passwordPolicyService.checkPasswordHistory(userId, newPassword);
    if (passwordHistoryCheck.isReuse) {
      throw new PasswordPolicyError(passwordHistoryCheck.issues || []);
    }

    // Hash and update password
    const hashedNewPassword = await passwordService.hash(newPassword);

    await prisma.user.update({
      where: { id: userId },
      data: { hashedPassword: hashedNewPassword }
    });

    // Save to password history
    await passwordPolicyService.savePasswordToHistory(userId, hashedNewPassword);

    // Invalidate all sessions
    await sessionService.deleteAllForUser(userId);

    await auditService.log({
      action: "password_changed",
      actorId: userId,
      ip,
      userAgent
    });
  },

  async verifyEmail(token: string): Promise<LoginFinalizationResult> {
    const tokenHash = hashTokenForDb(token);

    const record = await prisma.token.findUnique({
      where: { tokenHash },
    });

    if (!record || record.used || record.type !== TokenType.VERIFY_EMAIL || record.expiresAt < new Date()) {
      throw new InvalidTokenError('This verification link is invalid or has expired.');
    }

    const user = await prisma.$transaction(async (tx) => {
      const updatedUser = await tx.user.update({
        where: { id: record.userId },
        data: { isVerified: true, emailVerified: new Date() },
        include: { profile: true, onboarding: true },
      });
      await tx.token.update({
        where: { id: record.id },
        data: { used: true }
      });
      return updatedUser;
    });

    await auditService.log({ action: "email_verified", actorId: record.userId });
    return finalizeLogin(user);
  },

  async requestPasswordReset(email: string, locale: Locale): Promise<void> {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      console.log(`Password reset requested for non-existent email: ${email}`);
      return;
    }
    await inngest.send({
      name: 'auth/password.reset_requested',
      data: { email: user.email, userId: user.id, locale },
    });
  },

  async resetPassword(rawToken: string, newPassword: string): Promise<void> {
    try {
      // Get user from token
      const tokenHash = hashTokenForDb(rawToken);
      const tokenRecord = await prisma.token.findUnique({
        where: { tokenHash },
        include: {
          user: { include: { profile: true } }
        }
      });
      if (!tokenRecord || tokenRecord.used || tokenRecord.type !== TokenType.RESET_PASSWORD || tokenRecord.expiresAt < new Date()) {
        throw new InvalidTokenError('This reset link is invalid or has expired.');
      }

      // Validate new password policy
      const passwordValidation = await passwordPolicyService.validatePassword(
        newPassword,
        {
          email: tokenRecord.user.email,
          firstName: tokenRecord.user.profile?.firstName || undefined,
          lastName: tokenRecord.user.profile?.lastName || undefined,
          username: tokenRecord.user.username || undefined
        }
      );

      if (!passwordValidation.isValid) {
        throw new PasswordPolicyError(passwordValidation.issues || []);
      }

      // Check password history
      const passwordHistoryCheck = await passwordPolicyService.checkPasswordHistory(tokenRecord.userId, newPassword);
      if (passwordHistoryCheck.isReuse) {
        throw new PasswordPolicyError(passwordHistoryCheck.issues || []);
      }

      const updatedUser = await passwordService.confirmReset(rawToken, newPassword);
      await sessionService.deleteAllForUser(updatedUser.id);

      // Save to password history
      await passwordPolicyService.savePasswordToHistory(updatedUser.id, newPassword);

      await auditService.log({ action: "password_reset_success", actorId: updatedUser.id });
    } catch (error) {
      if (error instanceof InvalidPasswordResetTokenError) {
        throw new InvalidTokenError(error.message);
      }
      throw error;
    }
  },

  async refresh(rawRefreshToken: string, ip?: string, userAgent?: string): Promise<LoginFinalizationResult> {
    const { sub: userId, jti: sessionId } = await verifyRefreshToken(rawRefreshToken);

    const session = await prisma.$transaction(async (tx) => {
      const currentSession = await tx.userSession.findUnique({ where: { id: sessionId } });

      if (!currentSession || currentSession.expiresAt < new Date()) {
        await auditService.log({ action: "refresh_token_reuse_or_invalid", actorId: userId, ip, userAgent });
        await tx.userSession.deleteMany({ where: { userId } });
        throw new InvalidTokenError("Invalid session.");
      }

      await tx.userSession.delete({ where: { id: sessionId } });
      return currentSession;
    });

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
      include: { profile: true, onboarding: true },
    });

    if (!user) throw new InvalidTokenError("User not found.");

    return finalizeLogin(user, ip, userAgent);
  },

  async logout(rawRefreshToken: string): Promise<void> {
    try {
      const { jti: sessionId, sub: userId } = await verifyRefreshToken(rawRefreshToken);
      await sessionService.delete(sessionId);
      await auditService.log({ action: "logout_success", actorId: userId });
    } catch (error) {
      if (error instanceof InvalidTokenError) return;
      throw error;
    }
  },

  async resendVerificationEmail(email: string, locale: Locale): Promise<void> {
    const user = await prisma.user.findUnique({ where: { email } });

    if (!user || user.isVerified) {
      return;
    }

    await inngest.send({
      name: 'auth/user.registered',
      data: { userId: user.id, locale },
    });
  },

  async getUserById(userId: string) {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      include: { profile: true, onboarding: true },
    });

    if (!user || !user.profile || !user.onboarding) return null;

    const permissions = Array.from(await rbacService.getPermissionsForRoles(user.roles));
    return toAuthUser(user, permissions, user.onboarding.isCompleted);
  },

  async createImpersonationSession(adminUserId: string, targetUserId: string) {
    const [adminUser, targetUser] = await Promise.all([
      prisma.user.findUnique({ where: { id: adminUserId }, include: { profile: true, onboarding: true } }),
      prisma.user.findUnique({ where: { id: targetUserId }, include: { profile: true, onboarding: true } }),
    ]);

    if (!adminUser || !targetUser || !targetUser.profile || !targetUser.onboarding) {
      throw new Error("Admin or target user not found.");
    }

    const permissionsSet = await rbacService.getPermissionsForRoles(targetUser.roles);
    const permissions = Array.from(permissionsSet) as PermissionString[];

    const session = await sessionService.create(adminUserId);

    const accessTokenPayload: AccessTokenPayload = {
      sub: adminUser.id,
      actAsSub: targetUser.id,
      isImpersonating: true,
      roles: targetUser.roles,
      permissions,
    };

    const accessToken = await signAccessToken(accessTokenPayload);
    const refreshToken = await signRefreshToken({ sub: adminUserId, jti: session.id });

    const authUser = toAuthUser(targetUser, permissions, targetUser.onboarding.isCompleted);

    return {
      authResponse: {
        user: authUser,
        accessToken,
        onboardingCompleted: targetUser.onboarding.isCompleted,
      },
      refreshToken,
    };
  },
};
'''
'''
// lib/services/auth/cookie.service.ts
import { AUTH_CONFIG } from "@/lib/config/auth.config";
import type { ResponseCookie } from "next/dist/compiled/@edge-runtime/cookies";

/** Prepares the session cookie for setting in a Next.js response. */
export function createSessionCookie(token: string): ResponseCookie {
  return {
    name: AUTH_CONFIG.SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    secure: AUTH_CONFIG.COOKIE_SECURE,
    path: '/',
    maxAge: 60 * 60 * 24 * 30, // 30 days
    sameSite: 'lax',
  };
}

/** Prepares a cookie for clearing, to be set in a Next.js response. */
export function clearSessionCookie(): ResponseCookie {
  return {
    name: AUTH_CONFIG.SESSION_COOKIE_NAME,
    value: '',
    httpOnly: true,
    path: '/',
    maxAge: 0,
  };
}
'''
'''
// lib/services/auth/device-management.service.ts
import { prisma } from '@/lib/db';
import { add } from 'date-fns';
import { auditService } from '@/lib/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';

export interface DeviceInfo {
    userAgent: string;
    ip: string;
    platform?: string;
    browser?: string;
    os?: string;
    device?: string;
    fingerprint?: string;
}

export interface TrustedDeviceConfig {
    maxDevices: number;
    trustDurationDays: number;
    requireVerificationForNewDevices: boolean;
}

const DEFAULT_CONFIG: TrustedDeviceConfig = {
    maxDevices: 5,
    trustDurationDays: 30,
    requireVerificationForNewDevices: true,
};

export class NewDeviceError extends Error {
    constructor(
        public deviceId: string,
        message = 'New device detected. Please verify this device.'
    ) {
        super(message);
        this.name = 'NewDeviceError';
    }
}

export const deviceManagementService = {
    async getConfig(): Promise<TrustedDeviceConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    parseDeviceInfo(userAgent: string, ip: string): DeviceInfo {
        // Simple parsing of user agent - in production, you might use a library like ua-parser-js
        const browserMatch = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/?([\d.]+)?/);
        const osMatch = userAgent.match(/\(([^)]+)\)/);
        const platformMatch = userAgent.match(/(Windows|Mac|Linux|Android|iOS)/);

        return {
            userAgent,
            ip,
            platform: platformMatch ? platformMatch[1] : 'Unknown',
            browser: browserMatch ? browserMatch[1] : 'Unknown',
            os: osMatch ? osMatch[1] : 'Unknown',
            device: 'Unknown' // Would need more sophisticated parsing to detect device type
        };
    },

    async getDeviceFingerprint(deviceInfo: DeviceInfo): Promise<string> {
        // Create a simple fingerprint from device info
        // In production, you might use more sophisticated fingerprinting
        const fingerprintString = `${deviceInfo.platform}-${deviceInfo.browser}-${deviceInfo.os}`;
        return require('crypto').createHash('sha256').update(fingerprintString).digest('hex');
    },

    async recordDevice(
        userId: string,
        deviceInfo: DeviceInfo,
        isTrusted: boolean = false
    ): Promise<{ isNewDevice: boolean; deviceId: string; requiresVerification?: boolean }> {
        const fingerprint = await this.getDeviceFingerprint(deviceInfo);
        const config = await this.getConfig();

        // Check if this device already exists for the user
        const existingDevice = await prisma.trustedDevice.findFirst({
            where: {
                userId,
                fingerprint
            }
        });

        if (existingDevice) {
            // Update last used timestamp
            await prisma.trustedDevice.update({
                where: { id: existingDevice.id },
                data: {
                    lastUsedAt: new Date(),
                    lastIp: deviceInfo.ip
                }
            });

            return {
                isNewDevice: false,
                deviceId: existingDevice.id
            };
        }

        // Check if user has reached max devices
        const deviceCount = await prisma.trustedDevice.count({
            where: { userId, isTrusted: true }
        });

        if (deviceCount >= config.maxDevices) {
            // Remove oldest device
            const oldestDevice = await prisma.trustedDevice.findFirst({
                where: { userId, isTrusted: true },
                orderBy: { lastUsedAt: 'asc' }
            });

            if (oldestDevice) {
                await prisma.trustedDevice.update({
                    where: { id: oldestDevice.id },
                    data: { isTrusted: false }
                });
            }
        }

        // Create new device record
        const newDevice = await prisma.trustedDevice.create({
            data: {
                userId,
                fingerprint,
                platform: deviceInfo.platform,
                browser: deviceInfo.browser,
                os: deviceInfo.os,
                lastIp: deviceInfo.ip,
                isTrusted,
                trustedAt: isTrusted ? new Date() : null,
                expiresAt: isTrusted ? add(new Date(), { days: config.trustDurationDays }) : null
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.NEW_DEVICE_DETECTED,
            actorId: userId,
            metadata: {
                deviceId: newDevice.id,
                platform: deviceInfo.platform,
                browser: deviceInfo.browser,
                ip: deviceInfo.ip
            }
        });

        return {
            isNewDevice: true,
            deviceId: newDevice.id,
            requiresVerification: config.requireVerificationForNewDevices && !isTrusted
        };
    },

    async trustDevice(userId: string, deviceId: string): Promise<void> {
        const config = await this.getConfig();

        await prisma.trustedDevice.update({
            where: {
                id: deviceId,
                userId // Ensure user can only trust their own devices
            },
            data: {
                isTrusted: true,
                trustedAt: new Date(),
                expiresAt: add(new Date(), { days: config.trustDurationDays })
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.DEVICE_TRUSTED,
            actorId: userId,
            metadata: { deviceId }
        });
    },

    async revokeDevice(userId: string, deviceId: string): Promise<void> {
        await prisma.trustedDevice.updateMany({
            where: {
                id: deviceId,
                userId // Ensure user can only revoke their own devices
            },
            data: {
                isTrusted: false,
                revokedAt: new Date()
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.DEVICE_REVOKED,
            actorId: userId,
            metadata: { deviceId }
        });
    },

    async isTrustedDevice(userId: string, deviceInfo: DeviceInfo): Promise<{ isTrusted: boolean; deviceId?: string }> {
        const fingerprint = await this.getDeviceFingerprint(deviceInfo);

        const device = await prisma.trustedDevice.findFirst({
            where: {
                userId,
                fingerprint,
                isTrusted: true,
                OR: [
                    { expiresAt: null },
                    { expiresAt: { gt: new Date() } }
                ]
            }
        });

        return {
            isTrusted: !!device,
            deviceId: device?.id
        };
    },

    async getUserDevices(userId: string): Promise<any[]> {
        return prisma.trustedDevice.findMany({
            where: { userId },
            orderBy: { lastUsedAt: 'desc' }
        });
    }
};
'''
'''
// lib/services/auth/jwt.service.ts
import { SignJWT, jwtVerify } from "jose";
import { AUTH_CONFIG } from "@/lib/config/auth.config";
import { AccessTokenPayload, RefreshTokenPayload } from "@/types/auth.types";
import { InvalidTokenError } from "@/lib/errors/auth.errors";

const accessSecret = new TextEncoder().encode(AUTH_CONFIG.ACCESS_SECRET);
const refreshSecret = new TextEncoder().encode(AUTH_CONFIG.REFRESH_SECRET);
const mfaSecret = new TextEncoder().encode(process.env.JWT_MFA_SECRET || "dev_mfa_secret");

export interface MfaTokenPayload {
  sub: string;
  type: "mfa";
}

export async function signAccessToken(payload: AccessTokenPayload): Promise<string> {
  return new SignJWT({ ...payload, type: "access" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(AUTH_CONFIG.ACCESS_TOKEN_EXPIRES as string)
    .sign(accessSecret);
}

export async function verifyAccessToken(token: string): Promise<AccessTokenPayload> {
  try {
    const { payload } = await jwtVerify(token, accessSecret);
    if (payload.type !== "access") {
      throw new Error("Invalid token type");
    }
    return payload as unknown as AccessTokenPayload;
  } catch {
    throw new InvalidTokenError();
  }
}

export async function signRefreshToken(payload: Omit<RefreshTokenPayload, "type">): Promise<string> {
  return new SignJWT({ ...payload, type: "refresh" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(AUTH_CONFIG.REFRESH_TOKEN_EXPIRES as string)
    .sign(refreshSecret);
}

export async function verifyRefreshToken(token: string): Promise<RefreshTokenPayload> {
  try {
    const { payload } = await jwtVerify(token, refreshSecret);
    if (payload.type !== "refresh") {
      throw new Error("Invalid token type");
    }
    return payload as unknown as RefreshTokenPayload;
  } catch {
    throw new InvalidTokenError();
  }
}

export async function signMfaToken(payload: { sub: string }): Promise<string> {
  return new SignJWT({ ...payload, type: "mfa" })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(mfaSecret);
}

export async function verifyMfaToken(token: string): Promise<MfaTokenPayload> {
  try {
    const { payload } = await jwtVerify(token, mfaSecret);
    if (payload.type !== "mfa") {
      throw new Error("Invalid token type");
    }
    return payload as unknown as MfaTokenPayload;
  } catch {
    throw new InvalidTokenError("Invalid or expired MFA token.");
  }
}
'''
'''
// lib/services/auth/oauth.service.ts
import { prisma } from '@/lib/db';
import { auditService } from '@/lib/services/audit.service';
import { Prisma } from '@prisma/client';
import { onboardingService } from '@/lib/services/onboarding/onboarding.service';
import { finalizeLogin, LoginFinalizationResult } from '@/lib/services/auth/auth.service';
import { deviceManagementService, DeviceInfo } from '@/lib/services/auth/device-management.service';

interface GoogleUserInfo {
  id: string;
  email: string;
  name: string;
  given_name: string;
  family_name: string;
  picture: string;
  verified_email: boolean;
}

interface FacebookUserInfo {
  id: string;
  email: string;
  name: string;
  first_name: string;
  last_name: string;
  picture: {
    data: {
      url: string;
    };
  };
}

interface MicrosoftUserInfo {
  id: string;
  displayName: string;
  givenName: string;
  surname: string;
  userPrincipalName: string;
  mail?: string;
  photo?: string;
}

export async function exchangeGoogleCode(
  code: string,
  redirectUri: string
): Promise<{ access_token: string; id_token: string }> {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('Google OAuth credentials not configured');
  }

  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to exchange Google code for tokens');
  }

  return response.json();
}

export async function exchangeFacebookCode(
  code: string,
  redirectUri: string
): Promise<{ access_token: string }> {
  const clientId = process.env.FACEBOOK_APP_ID;
  const clientSecret = process.env.FACEBOOK_APP_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('Facebook OAuth credentials not configured');
  }

  const response = await fetch('https://graph.facebook.com/v18.0/oauth/access_token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to exchange Facebook code for tokens');
  }

  return response.json();
}

export async function exchangeMicrosoftCode(
  code: string,
  redirectUri: string
): Promise<{ access_token: string; id_token: string }> {
  const clientId = process.env.MICROSOFT_CLIENT_ID;
  const clientSecret = process.env.MICROSOFT_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error('Microsoft OAuth credentials not configured');
  }

  const response = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      code,
      client_id: clientId,
      client_secret: clientSecret,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to exchange Microsoft code for tokens');
  }

  return response.json();
}

export async function getGoogleUserInfo(accessToken: string): Promise<GoogleUserInfo> {
  const response = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Google user info');
  }

  return response.json();
}

export async function getFacebookUserInfo(accessToken: string): Promise<FacebookUserInfo> {
  const response = await fetch(
    `https://graph.facebook.com/me?fields=id,name,email,first_name,last_name,picture&access_token=${accessToken}`
  );

  if (!response.ok) {
    throw new Error('Failed to fetch Facebook user info');
  }

  return response.json();
}

export async function getMicrosoftUserInfo(accessToken: string): Promise<MicrosoftUserInfo> {
  const response = await fetch('https://graph.microsoft.com/v1.0/me', {
    headers: {
      Authorization: `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    throw new Error('Failed to fetch Microsoft user info');
  }

  return response.json();
}

interface NormalizedUserInfo {
  email: string;
  firstName?: string;
  lastName?: string;
  avatarUrl?: string;
}

export const oauthService = {
  exchangeGoogleCode,
  getGoogleUserInfo,
  exchangeFacebookCode,
  getFacebookUserInfo,
  exchangeMicrosoftCode,
  getMicrosoftUserInfo,

  async handleLogin(
    provider: 'google' | 'facebook' | 'microsoft',
    userInfo: NormalizedUserInfo,
    deviceInfo: DeviceInfo,
    ip?: string,
    userAgent?: string
  ): Promise<LoginFinalizationResult> {
    const email = userInfo.email?.toLowerCase().trim();
    if (!email) {
      // This is an internal error, not a user-facing one.
      throw new Error('Email not provided by OAuth provider.');
    }

    let user = await prisma.user.findUnique({
      where: { email },
      include: { profile: true, onboarding: true }
    });

    if (!user) {
      const initialOnboardingSteps = onboardingService.generateStepsForRole(null);

      user = await prisma.user.create({
        data: {
          email,
          isVerified: true, // OAuth emails are considered verified
          emailVerified: new Date(),
          avatar: userInfo.avatarUrl,
          roles: [],
          profile: {
            create: {
              firstName: userInfo.firstName,
              lastName: userInfo.lastName,
              avatarUrl: userInfo.avatarUrl,
            }
          },
          onboarding: {
            create: {
              steps: initialOnboardingSteps as unknown as Prisma.JsonArray,
            },
          },
        },
        include: { profile: true, onboarding: true }
      });

      await auditService.log({
        action: 'oauth_user_created',
        actorId: user.id,
        metadata: { provider, ip }
      });

    } else {
      const profileUpdates: Prisma.UserProfileUpdateInput = {};
      if (userInfo.firstName && !user.profile?.firstName) {
        profileUpdates.firstName = userInfo.firstName;
      }
      if (userInfo.lastName && !user.profile?.lastName) {
        profileUpdates.lastName = userInfo.lastName;
      }
      if (userInfo.avatarUrl && userInfo.avatarUrl !== user.profile?.avatarUrl) {
        profileUpdates.avatarUrl = userInfo.avatarUrl;
      }

      if (Object.keys(profileUpdates).length > 0 || (userInfo.avatarUrl && userInfo.avatarUrl !== user.avatar)) {
        await prisma.user.update({
          where: { id: user.id },
          data: {
            // Also update the core avatar for consistency
            avatar: userInfo.avatarUrl,
            profile: {
              update: profileUpdates,
            }
          }
        });
      }
    }

    // Record device information
    const deviceResult = await deviceManagementService.recordDevice(
      user.id,
      deviceInfo,
      false // OAuth devices are not automatically trusted
    );

    // Create or update OAuth account
    await prisma.account.upsert({
      where: {
        provider_providerAccountId: {
          provider: provider.toUpperCase(),
          providerAccountId: userInfo.email
        }
      },
      update: {
        // Update any necessary fields
      },
      create: {
        userId: user.id,
        provider: provider.toUpperCase(),
        providerAccountId: userInfo.email,
      }
    });

    await auditService.log({
      action: 'oauth_login_attempt',
      actorId: user.id,
      metadata: { provider, ip, deviceId: deviceResult.deviceId }
    });

    const loginResult = await finalizeLogin(user, ip, userAgent);

    // Add device information to the response
    return {
      ...loginResult,
      deviceInfo: {
        isNewDevice: deviceResult.isNewDevice,
        deviceId: deviceResult.deviceId,
        requiresVerification: deviceResult.requiresVerification
      }
    };
  }
};
'''
'''
// lib/services/auth/password-policy.service.ts
import { prisma } from '@/lib/db';
import bcrypt from 'bcryptjs';
import z from 'zod';

export interface PasswordPolicyConfig {
    minLength: number;
    requireUppercase: boolean;
    requireLowercase: boolean;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
    preventCommonPasswords: boolean;
    preventUserInfo: boolean;
    maxAgeDays?: number;
    preventReuse: number; // Number of previous passwords to check
}

const DEFAULT_CONFIG: PasswordPolicyConfig = {
    minLength: 8,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    preventCommonPasswords: true,
    preventUserInfo: true,
    maxAgeDays: 90,
    preventReuse: 5,
};

// List of common passwords to prevent
const COMMON_PASSWORDS = [
    'password', '123456', '123456789', 'qwerty', 'password123',
    'admin', 'letmein', 'welcome', 'monkey', '1234567890'
];

export class PasswordPolicyError extends Error {
    constructor(
        public issues: string[],
        message = 'Password does not meet security requirements'
    ) {
        super(message);
        this.name = 'PasswordPolicyError';
    }
}

export const passwordPolicyService = {
    async getConfig(): Promise<PasswordPolicyConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    async validatePassword(
        password: string,
        userInfo?: { email?: string; firstName?: string; lastName?: string; username?: string }
    ): Promise<{ isValid: boolean; issues?: string[] }> {
        const config = await this.getConfig();
        const issues: string[] = [];

        // Check minimum length
        if (password.length < config.minLength) {
            issues.push(`Password must be at least ${config.minLength} characters long`);
        }

        // Check for uppercase letters
        if (config.requireUppercase && !/[A-Z]/.test(password)) {
            issues.push('Password must contain at least one uppercase letter');
        }

        // Check for lowercase letters
        if (config.requireLowercase && !/[a-z]/.test(password)) {
            issues.push('Password must contain at least one lowercase letter');
        }

        // Check for numbers
        if (config.requireNumbers && !/\d/.test(password)) {
            issues.push('Password must contain at least one number');
        }

        // Check for special characters
        if (config.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
            issues.push('Password must contain at least one special character');
        }

        // Check against common passwords
        if (config.preventCommonPasswords) {
            const lowerPassword = password.toLowerCase();
            if (COMMON_PASSWORDS.some(common => lowerPassword.includes(common))) {
                issues.push('Password cannot contain common words or patterns');
            }
        }

        // Check for user information
        if (config.preventUserInfo && userInfo) {
            const lowerPassword = password.toLowerCase();
            const { email, firstName, lastName, username } = userInfo;

            if (email && lowerPassword.includes(email.split('@')[0].toLowerCase())) {
                issues.push('Password cannot contain parts of your email address');
            }

            if (firstName && lowerPassword.includes(firstName.toLowerCase())) {
                issues.push('Password cannot contain your first name');
            }

            if (lastName && lowerPassword.includes(lastName.toLowerCase())) {
                issues.push('Password cannot contain your last name');
            }

            if (username && lowerPassword.includes(username.toLowerCase())) {
                issues.push('Password cannot contain your username');
            }
        }

        return {
            isValid: issues.length === 0,
            issues: issues.length > 0 ? issues : undefined
        };
    },

    async checkPasswordHistory(userId: string, newPassword: string): Promise<{ isReuse: boolean; issues?: string[] }> {
        const config = await this.getConfig();

        if (config.preventReuse <= 0) {
            return { isReuse: false };
        }

        // Get user's password history
        const passwordHistory = await prisma.passwordHistory.findMany({
            where: { userId },
            orderBy: { createdAt: 'desc' },
            take: config.preventReuse
        });

        // Check if new password matches any previous passwords
        for (const entry of passwordHistory) {
            const isMatch = await bcrypt.compare(newPassword, entry.hashedPassword);
            if (isMatch) {
                return {
                    isReuse: true,
                    issues: [`You cannot reuse a password from your last ${config.preventReuse} passwords`]
                };
            }
        }

        return { isReuse: false };
    },

    async savePasswordToHistory(userId: string, hashedPassword: string): Promise<void> {
        // Add new password to history
        await prisma.passwordHistory.create({
            data: {
                userId,
                hashedPassword
            }
        });

        // Clean up old password history entries (keep only the last N)
        const config = await this.getConfig();
        if (config.preventReuse > 0) {
            const historyEntries = await prisma.passwordHistory.findMany({
                where: { userId },
                orderBy: { createdAt: 'desc' }
            });

            if (historyEntries.length > config.preventReuse) {
                const entriesToDelete = historyEntries.slice(config.preventReuse);
                const idsToDelete = entriesToDelete.map(entry => entry.id);

                await prisma.passwordHistory.deleteMany({
                    where: {
                        id: { in: idsToDelete }
                    }
                });
            }
        }
    }
};
'''
'''
import bcrypt from 'bcryptjs';
import { prisma } from '@/lib/db';
import { generateRandomToken, hashTokenForDb } from '@/lib/utils/auth.utils';
import { add } from 'date-fns';
import { TokenType, User } from '@prisma/client';
import { InvalidTokenError } from '@/lib/errors/auth.errors';

const SALT_ROUNDS = 12;
const PASSWORD_RESET_TOKEN_BYTES = 32;
const PASSWORD_RESET_TOKEN_EXPIRES_IN_HOURS = 2;
const VERIFICATION_TOKEN_BYTES = 32;
const VERIFICATION_TOKEN_EXPIRES_IN_HOURS = 24;

export class InvalidPasswordResetTokenError extends Error {
  constructor(message = 'Invalid or expired password reset token.') {
    super(message);
    this.name = 'InvalidPasswordResetTokenError';
  }
}

export const passwordService = {
  async hash(password: string): Promise<string> {
    return bcrypt.hash(password, SALT_ROUNDS);
  },

  async compare(password: string, hash: string): Promise<boolean> {
    return bcrypt.compare(password, hash);
  },

  async createVerificationToken(userId: string): Promise<string> {
    const rawToken = generateRandomToken(VERIFICATION_TOKEN_BYTES);
    const tokenHash = hashTokenForDb(rawToken);
    const expiresAt = add(new Date(), { hours: VERIFICATION_TOKEN_EXPIRES_IN_HOURS });

    await prisma.$transaction([
      // Invalidate any old verification tokens for this user
      prisma.token.deleteMany({
        where: { userId, type: TokenType.VERIFY_EMAIL },
      }),
      // Create the new one
      prisma.token.create({
        data: {
          userId,
          type: TokenType.VERIFY_EMAIL,
          tokenHash,
          expiresAt,
        },
      }),
    ]);

    return rawToken;
  },

  async createPasswordResetToken(userId: string): Promise<string> {
    const rawToken = generateRandomToken(PASSWORD_RESET_TOKEN_BYTES);
    const tokenHash = hashTokenForDb(rawToken);
    const expiresAt = add(new Date(), { hours: PASSWORD_RESET_TOKEN_EXPIRES_IN_HOURS });

    await prisma.$transaction([
      // Invalidate any other pending password reset tokens for this user
      prisma.token.updateMany({
        where: { userId, type: TokenType.RESET_PASSWORD, used: false },
        data: { used: true },
      }),
      // Create the new token
      prisma.token.create({
        data: {
          userId,
          type: TokenType.RESET_PASSWORD,
          tokenHash,
          expiresAt,
        },
      }),
    ]);

    return rawToken;
  },

  async validatePasswordResetToken(rawToken: string) {
    const tokenHash = hashTokenForDb(rawToken);
    const tokenRecord = await prisma.token.findUnique({
      where: { tokenHash },
    });

    if (!tokenRecord || tokenRecord.used || tokenRecord.expiresAt < new Date()) {
      throw new InvalidPasswordResetTokenError();
    }

    return tokenRecord;
  },

  async confirmReset(rawToken: string, newPassword: string): Promise<User> {
    const tokenHash = hashTokenForDb(rawToken);

    const updatedUser = await prisma.$transaction(async (tx) => {
      const tokenRecord = await tx.token.findUnique({
        where: { tokenHash },
      });

      // Check type, usage, and expiry
      if (!tokenRecord || tokenRecord.type !== TokenType.RESET_PASSWORD || tokenRecord.used || tokenRecord.expiresAt < new Date()) {
        throw new InvalidTokenError();
      }

      const newHashedPassword = await this.hash(newPassword);

      const user = await tx.user.update({
        where: { id: tokenRecord.userId },
        data: { hashedPassword: newHashedPassword },
      });

      // Mark the token as used
      await tx.token.update({
        where: { id: tokenRecord.id },
        data: { used: true },
      });

      // For added security, invalidate all active sessions for the user after a password reset
      await tx.userSession.deleteMany({
        where: { userId: tokenRecord.userId },
      });

      return user;
    });

    return updatedUser;
  },
};
'''
'''
// lib/services/auth/rbac.service.ts
import 'server-only';
import { prisma } from "@/lib/db";
import { Role } from "@prisma/client";
import { LRUCache } from 'lru-cache';
import type { PermissionString } from '@/lib/audit/actions';
import { logger } from '@/lib/logger';

const rolePermissionsCache = new LRUCache<Role, PermissionString[]>({
  max: 100,
  ttl: 1000 * 60 * 5,
});

class RBACService {
  async getPermissionsForRoles(roles: Role[]): Promise<Set<PermissionString>> {
    const allPermissions = new Set<PermissionString>();

    if (!roles || roles.length === 0) {
      return allPermissions;
    }

    for (const role of roles) {
      if (rolePermissionsCache.has(role)) {
        rolePermissionsCache.get(role)!.forEach(p => allPermissions.add(p));
        continue;
      }

      const rolePerms = await prisma.rolePermission.findMany({
        where: { role },
        include: { permission: true },
      });

      const permissions = rolePerms.map(
        rp => `${rp.permission.resource}:${rp.permission.action}` as PermissionString
      );

      rolePermissionsCache.set(role, permissions);
      permissions.forEach(p => allPermissions.add(p));
    }

    return allPermissions;
  }


  async startImpersonation(adminUserId: string, targetUserId: string): Promise<void> {
    const adminUser = await prisma.user.findUnique({ where: { id: adminUserId } });
    if (!adminUser || !adminUser.roles.includes(Role.SUPER_ADMIN)) {
      throw new Error("Forbidden: Only Super Admins can impersonate users.");
    }

    await prisma.user.update({
      where: { id: adminUserId },
      data: { impersonatingUserId: targetUserId },
    });
  }

  async stopImpersonation(adminUserId: string): Promise<void> {
    await prisma.user.update({
      where: { id: adminUserId },
      data: { impersonatingUserId: null },
    });
  }

  async invalidateCacheForRole(role: Role): Promise<void> {
    rolePermissionsCache.delete(role);
    logger.info({ role }, `[RBAC Cache] Invalidated cache for role`);
  }
}

export const rbacService = new RBACService();
'''
'''
// lib/auth/sessions/session.service.ts
import { prisma } from "@/lib/db";
import { add } from "date-fns";
import { AUTH_CONFIG } from "../../config/auth.config";
import type { UserSession } from "@prisma/client";
import crypto from "crypto";

export const sessionService = {
  async create(userId: string, ipAddress?: string, userAgent?: string): Promise<UserSession> {
    const expiresIn = AUTH_CONFIG.REFRESH_TOKEN_EXPIRES;
    let expiresAt: Date;

    if (typeof expiresIn === "string" && expiresIn.endsWith("d")) {
      expiresAt = add(new Date(), { days: parseInt(expiresIn) });
    } else {
      expiresAt = add(new Date(), { seconds: Number(expiresIn) || 2592000 }); 
    }

    const sessionToken = crypto.randomBytes(32).toString("hex");

    return prisma.userSession.create({
      data: {
        sessionToken,
        userId,
        expiresAt,
        ipAddress,
        userAgent,
      },
    });
  },

  async getById(sessionId: string): Promise<UserSession | null> {
    const session = await prisma.userSession.findUnique({
      where: { id: sessionId },
    });

    if (!session || session.expiresAt < new Date()) {
      if (session) await this.delete(sessionId);
      return null;
    }

    return session;
  },

  async delete(sessionId: string): Promise<UserSession | null> {
    try {
      return await prisma.userSession.delete({ where: { id: sessionId } });
    } catch {
      return null;
    }
  },
  async deleteAllForUser(userId: string): Promise<{ count: number }> {
    return prisma.userSession.deleteMany({
      where: { userId },
    });
  },
};
'''
'''
// lib/services/auth/totp.service.ts
import { authenticator } from "otplib";
import qrcode from "qrcode";

export function generateTotpSecret() {
  return authenticator.generateSecret();
}

export function getTotpUri(secret: string, userEmail: string, issuer = "AWE e.V.") {
  return authenticator.keyuri(userEmail, issuer, secret);
}

export async function getQrCodeDataUrl(uri: string) {
  return qrcode.toDataURL(uri);
}

export function verifyTotpToken(secret: string, token: string) {
  return authenticator.check(token, secret);
}
'''
'''
// lib/services/rate-limit/config.ts
import type { IRateLimiterOptions } from "rate-limiter-flexible";
import { ENV } from "./env";

export const LOGIN_LIMITER_OPTS: IRateLimiterOptions = {
  keyPrefix: "rl:login",
  points: ENV.RATE_LIMIT_LOGIN_MAX,
  duration: ENV.RATE_LIMIT_LOGIN_WINDOW,
  blockDuration: ENV.RATE_LIMIT_LOGIN_WINDOW, 
};

export const GLOBAL_LIMITER_OPTS: IRateLimiterOptions = {
  keyPrefix: "rl:global",
  points: ENV.RATE_LIMIT_GLOBAL_MAX,
  duration: ENV.RATE_LIMIT_GLOBAL_WINDOW,
  blockDuration: ENV.RATE_LIMIT_GLOBAL_WINDOW,
};
'''
'''
// lib/services/rate-limit/consume.ts
import { RateLimiterRes } from 'rate-limiter-flexible';
import { getLoginLimiter, getGlobalLimiter } from './limiters';
import { pino } from 'pino';

const logger = pino({ name: 'rate-limit' });

export type LimiterDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

function rejectionToDecision(rej: unknown): LimiterDecision {
  if (rej instanceof RateLimiterRes) {
    const secs = Math.ceil(rej.msBeforeNext / 1000) || 1;
    return { allowed: false, retryAfterSeconds: secs };
  }
  logger.error({ err: rej }, 'Unexpected rate-limiter error');
  return { allowed: false, retryAfterSeconds: 60 };
}

export async function consumeLogin(key: string): Promise<LimiterDecision> {
  try {
    await getLoginLimiter().consume(key);
    return { allowed: true };
  } catch (rej) {
    return rejectionToDecision(rej);
  }
}

export async function consumeGlobal(key: string): Promise<LimiterDecision> {
  try {
    await getGlobalLimiter().consume(key);
    return { allowed: true };
  } catch (rej) {
    return rejectionToDecision(rej);
  }
}
'''
'''
// lib/services/rate-limit/env.ts
import { z } from "zod";

const schema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  REDIS_URL: z.string().url(),

  RATE_LIMIT_LOGIN_MAX: z.coerce.number().int().positive().default(5),
  RATE_LIMIT_LOGIN_WINDOW: z.coerce.number().int().positive().default(60),
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().int().positive().default(100),
  RATE_LIMIT_GLOBAL_WINDOW: z.coerce.number().int().positive().default(60),
});

export const ENV = schema.parse(process.env);
'''
'''
// lib/services/rate-limit/index.ts
export { consumeLogin, consumeGlobal, type LimiterDecision } from './consume';

'''
'''
// lib/services/rate-limit/limiters.ts
import { RateLimiterRedis } from 'rate-limiter-flexible';
import { getRedis } from './redis';
import { LOGIN_LIMITER_OPTS, GLOBAL_LIMITER_OPTS } from './config';

let login: RateLimiterRedis | undefined;
let global: RateLimiterRedis | undefined;

export function getLoginLimiter(): RateLimiterRedis {
  if (!login) login = new RateLimiterRedis({ ...LOGIN_LIMITER_OPTS, storeClient: getRedis() });
  return login;
}

export function getGlobalLimiter(): RateLimiterRedis {
  if (!global) global = new RateLimiterRedis({ ...GLOBAL_LIMITER_OPTS, storeClient: getRedis() });
  return global;
}

/* ------------------------------------------------------------------ */
/*  Nothing to shut down on the limiter itself – Redis is disconnected
    globally once, usually in your graceful-shutdown hook.            */
/* ------------------------------------------------------------------ */
export async function closeLimiters(): Promise<void> {
}
'''
'''
// lib/services/rate-limit/redis.ts
import Redis from 'ioredis';
import { ENV } from './env';
import { pino } from 'pino';

const logger = pino({ name: 'redis' });

function createRedis(): Redis {
  const client = new Redis(ENV.REDIS_URL, {
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  });

  client.on('error', (err) => logger.error({ err }, 'Redis client error'));
  client.on('connect', () => logger.info('Redis connected'));
  client.on('close', () => logger.warn('Redis connection closed'));
  return client;
}

let _redis: Redis | undefined;
export function getRedis(): Redis {
  if (!_redis) _redis = createRedis();
  return _redis;
}

export async function pingRedis(): Promise<boolean> {
  try {
    return (await getRedis().ping()) === 'PONG';
  } catch {
    return false;
  }
}
'''
'''
// lib/services/audit.service.ts
import { NextRequest } from 'next/server';
import { posthog } from '@/lib/posthog';
import { prisma } from '@/lib/db';
import type { Prisma } from '@prisma/client';
import { logger } from '@/lib/logger';
import * as Sentry from '@sentry/nextjs';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import { InngestEvent } from '@/inngest/client';

const SENSITIVE_ACTIONS = new Set<string>([
    AUDIT_ACTIONS.LOGIN_FAILED,
    AUDIT_ACTIONS.PASSWORD_RESET_SUCCESS,
]);

function sanitizeMetadata(metadata?: Record<string, unknown> | null): Record<string, unknown> | null {
    if (!metadata) return null;
    const clone = { ...metadata };
    const sensitiveKeys = ['password', 'token', 'secret', 'authorization', 'code', 'oldPassword', 'newPassword'];
    for (const key of sensitiveKeys) {
        if (key in clone) clone[key] = '[REDACTED]';
    }
    return clone;
}

export interface AuditEvent {
    action: string;
    actorId?: string | null;
    ip?: string | null;
    userAgent?: string | null;
    requestId?: string;
    inngestRunId?: string;
    metadata?: Record<string, unknown> | null;
}

class AuditService {
    public async log(event: AuditEvent): Promise<void> {
        const sanitizedMetadata = sanitizeMetadata(event.metadata);
        logger.info({ ...event, metadata: sanitizedMetadata }, `[AUDIT] ${event.action}`);

        await this._logToDatabase(event, sanitizedMetadata);
        await this._logToAnalytics(event, sanitizedMetadata);
    }

    private async _logToDatabase(event: AuditEvent, sanitizedMetadata: Record<string, unknown> | null) {
        try {
            await prisma.auditLog.create({
                data: {
                    action: event.action,
                    actor: event.actorId ? { connect: { id: event.actorId } } : undefined,
                    meta: {
                        ip: event.ip,
                        userAgent: event.userAgent,
                        requestId: event.requestId,
                        inngestRunId: event.inngestRunId,
                        ...sanitizedMetadata,
                    } as Prisma.JsonObject,
                },
            });
        } catch (dbError) {
            logger.error({ err: dbError, event }, '[AUDIT-DB-ERROR] Failed to write audit log to database.');
            Sentry.captureException(dbError, { extra: { event, reason: 'Audit Log DB Write Failure' } });
        }
    }

    private async _logToAnalytics(event: AuditEvent, sanitizedMetadata: Record<string, unknown> | null) {
        if (posthog && !SENSITIVE_ACTIONS.has(event.action) && process.env.NODE_ENV === 'production') {
            try {
                posthog.capture({
                    distinctId: event.actorId || event.ip || 'anonymous',
                    event: event.action,
                    properties: { ...event, metadata: sanitizedMetadata, $ip: event.ip },
                });
            } catch (posthogError) {
                logger.error({ err: posthogError, event }, '[AUDIT-POSTHOG-ERROR] Failed to send audit log to PostHog.');
                Sentry.captureException(posthogError, { extra: { event, reason: 'Audit Log PostHog Write Failure' } });
            }
        }
    }

    public fromRequest(
        req: NextRequest,
        action: string,
        actorId?: string | null,
        metadata?: Record<string, unknown> | null,
    ): void {
        const ip =
            req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
            req.headers.get('x-real-ip') ||
            '127.0.0.1';
        const userAgent = req.headers.get('user-agent') || null;
        const requestId = req.headers.get('x-request-id') || crypto.randomUUID();

        this.log({ action, actorId, metadata, ip, userAgent, requestId });
    }

    public fromInngest(
        inngestEvent: InngestEvent,
        runId: string,
        action: string,
        actorId?: string | null,
        metadata?: Record<string, unknown> | null,
    ): void {
        this.log({
            action,
            actorId,
            metadata: { ...metadata, originalEventName: inngestEvent.name },
            inngestRunId: runId,
        });
    }
}

export const auditService = new AuditService();
'''
'''
// lib/auth/auth.utils.ts
import crypto from "crypto";

export function hashTokenForDb(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function generateRandomToken(bytes = 48) {
  return crypto.randomBytes(bytes).toString("hex");
}

'''
'''
// lib/auth/permissions.utils.ts
import { PERMISSIONS } from '@/lib/audit/actions';
import type { PermissionString } from '@/lib/audit/actions';

export function hasPermission(
    userPermissions: Set<PermissionString>,
    requiredPermission: PermissionString
): boolean {
    if (userPermissions.has(PERMISSIONS.ALL_MANAGE)) {
        return true;
    }

    if (userPermissions.has(requiredPermission)) {
        return true;
    }

    const resource = requiredPermission.split(':')[0];
    const managePermission = `${resource}:manage` as PermissionString;
    if (userPermissions.has(managePermission)) {
        return true;
    }

    return false;
}
'''
'''
// lib/schemas/auth.schemas.ts 
import { z } from "zod";

export const signUpSchema = z.object({
  email: z.string().email({ message: 'Please enter a valid email address.' }),
  password: z.string().min(8, { message: 'Password must be at least 8 characters.' }),
  confirmPassword: z.string(),
})
  .refine((data) => data.password === data.confirmPassword, {
    message: "Passwords do not match.",
    path: ["confirmPassword"],
  });

export const loginSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
  password: z.string().min(1, "Password is required."),
  rememberMe: z.boolean().optional(),
});

export const mfaVerifySchema = z.object({
  code: z.string().length(6, "MFA code must be 6 digits.").regex(/^\d{6}$/),
  mfaToken: z.string(),
});

export const passwordResetSchema = z.object({
  oldPassword: z.string().min(8, "Old password must be at least 8 characters long."),
  newPassword: z.string().min(8, "New password must be at least 8 characters long."),
})

export const passwordResetRequestSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
});

export const passwordResetConfirmSchema = z.object({
  token: z.string().min(1, "Reset token is required."),
  newPassword: z.string().min(8, "New password must be at least 8 characters long."),
  confirmPassword: z.string().min(8, "Password must be at least 8 characters long."),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords do not match.",
  path: ["confirmPassword"],
});

export const sendVerificationSchema = z.object({
  email: z.string().email("Invalid email address.").transform(v => v.toLowerCase().trim()),
});

export const oauthInitiateSchema = z.object({
  returnTo: z.string().optional(),
});

export const resendVerificationSchema = z.object({
  email: z.string().email('Please enter a valid email address.'),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, "Current password is required"),
  newPassword: z.string().min(8, "New password must be at least 8 characters"),
  confirmPassword: z.string().min(1, "Password confirmation is required"),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: "Passwords don't match",
  path: ["confirmPassword"],
});

export const verifyDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
  code: z.string().optional(),
});

export const trustDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
});

export const revokeDeviceSchema = z.object({
  deviceId: z.string().min(1, "Device ID is required"),
});
'''
'''
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
'''
'''
// lib/errors/auth.errors.ts 
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
  }
}

export class InvalidCredentialsError extends AuthError {
  public code?: string;

  constructor(message = 'Invalid email or password.', code?: string) {
    super(message);
    this.name = 'InvalidCredentialsError';
    this.code = code;
  }
}

export class AccountExistsError extends AuthError {
  constructor(message = 'An account with this email already exists.') {
    super(message);
    this.name = 'AccountExistsError';
  }
}

export class InvalidTokenError extends AuthError {
  constructor(message = 'The provided token is invalid or has expired.') {
    super(message);
    this.name = 'InvalidTokenError';
  }
}

export class MfaRequiredError extends AuthError {
  public mfaToken: string;

  constructor(mfaToken: string, message = 'Multi-factor authentication is required.') {
    super(message);
    this.name = 'MfaRequiredError';
    this.mfaToken = mfaToken;
  }
}

export class AccountExistsVerifiedError extends AccountExistsError {
  constructor(message = 'This account already exists. Please log in.') {
    super(message);
    this.name = 'AccountExistsVerifiedError';
  }
}

export class AccountExistsUnverifiedError extends AccountExistsError {
  constructor(message = 'Account exists but is not verified. A new verification email has been sent.') {
    super(message);
    this.name = 'AccountExistsUnverifiedError';
  }
}

export class PasswordPolicyError extends Error {
  constructor(
    public issues: string[],
    message = 'Password does not meet security requirements'
  ) {
    super(message);
    this.name = 'PasswordPolicyError';
  }
}

export class AccountLockedError extends Error {
  constructor(
    public lockedUntil: Date,
    message = 'Account has been temporarily locked due to too many failed login attempts. Please try again later.'
  ) {
    super(message);
    this.name = 'AccountLockedError';
  }
}

export class NewDeviceError extends Error {
  constructor(
    public deviceId: string,
    message = 'New device detected. Please verify this device.'
  ) {
    super(message);
    this.name = 'NewDeviceError';
  }
}
'''
'''
// lib/errors/errors.ts

/**
 * Base class for all application-specific errors.
 * Allows for consistent error handling and structured error responses.
 */
export class AppError extends Error {
    public readonly code: string;
    public readonly statusCode: number;
    public readonly details?: unknown;

    constructor(message: string, code: string, statusCode: number, details?: unknown) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Thrown when a resource is not found.
 * HTTP Status: 404
 */
export class NotFoundError extends AppError {
    constructor(resource: string = 'Resource') {
        super(`${resource} not found`, `${resource.toUpperCase()}_NOT_FOUND`, 404);
    }
}

/**
 * Thrown when input data fails validation.
 * HTTP Status: 400
 */
export class ValidationError extends AppError {
    constructor(message: string, details?: unknown) {
        super(message, 'VALIDATION_ERROR', 400, details);
    }
}

/**
 * Thrown when a user is not authorized to perform an action.
 * HTTP Status: 403
 */
export class ForbiddenError extends AppError {
    constructor(message: string = 'You do not have permission to perform this action.') {
        super(message, 'FORBIDDEN', 403);
    }
}

/**
 * Thrown for general server-side errors.
 * HTTP Status: 500
 */
export class InternalServerError extends AppError {
    constructor(message: string = 'An unexpected internal error occurred.') {
        super(message, 'INTERNAL_SERVER_ERROR', 500);
    }
}
'''
'''
// lib/db/config.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
    prisma: PrismaClient | undefined;
};

function createPrismaClient() {
    const isProduction = process.env.NODE_ENV === 'production';

    return new PrismaClient({
        log: isProduction ? ['error'] : ['query', 'info', 'warn', 'error'],
        errorFormat: 'pretty',
    });
}

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') {
    globalForPrisma.prisma = prisma;
}
'''
'''
// lib/db/index.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
  prisma: PrismaClient | undefined;
};

export const prisma = globalForPrisma.prisma ?? new PrismaClient();

if (process.env.NODE_ENV !== 'production') globalForPrisma.prisma = prisma;

'''
'''
// lib/config/auth.config.ts
export const AUTH_CONFIG = {
  ACCESS_TOKEN_EXPIRES: (process.env.ACCESS_TOKEN_EXPIRES_IN || "15m") as string | number,
  REFRESH_TOKEN_EXPIRES: (process.env.REFRESH_TOKEN_EXPIRES_IN || "30d") as string | number,
  ACCESS_SECRET: process.env.JWT_ACCESS_SECRET || "dev_access_secret",
  REFRESH_SECRET: process.env.JWT_REFRESH_SECRET || "dev_refresh_secret",
  SESSION_COOKIE_NAME: process.env.SESSION_COOKIE_NAME || "awe_session",
  COOKIE_SECURE: process.env.SESSION_COOKIE_SECURE === "true",
  RATE_LIMIT_POINTS: Number(process.env.RATE_LIMIT_POINTS || 5),
  RATE_LIMIT_DURATION: Number(process.env.RATE_LIMIT_DURATION || 60), // seconds

  REFRESH_COOKIE_NAME: 'awe_refresh',
  MFA_COOKIE_NAME: 'awe_mfa',

  PASSWORD_MIN_LENGTH: 8,
  PASSWORD_MAX_AGE: 90, // days
  MAX_LOGIN_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes

  MFA_ISSUER: 'AWE e.V.',
  MFA_DIGITS: 6,
  MFA_WINDOW: 1,
} as const;

export const SALT_ROUNDS = 12;
'''
'''
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

} as const;

export type AuditActionString = typeof AUDIT_ACTIONS[keyof typeof AUDIT_ACTIONS];
'''
'''
// lib/api-client/base.ts

import { useAuthStore } from "@/stores/auth.store";
import type { LoginResponse } from "@/types/auth.types";
import { ApiClientError, type ApiErrorPayload } from "./errors";

// Define custom options that extend the native RequestInit
export interface ApiClientOptions extends RequestInit {
    skipAuthRefresh?: boolean;
}

type FailedRequestQueue = ((token: string | null) => void)[];

let isRefreshing = false;
let failedQueue: FailedRequestQueue = [];

const processQueue = (error: Error | null, token: string | null = null) => {
    failedQueue.forEach(callback => callback(token));
    failedQueue = [];
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

export async function apiClient<T>(endpoint: string, options: ApiClientOptions = {}): Promise<T> {
    const { accessToken, logout, setAuth } = useAuthStore.getState();
    const { skipAuthRefresh, ...fetchOptions } = options;
    const url = `${API_BASE_URL}${endpoint}`;

    const headers = new Headers(fetchOptions.headers);
    if (accessToken && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${accessToken}`);
    }

    const response = await fetch(url, { ...fetchOptions, headers, credentials: 'include' as const });

    if (response.ok) {
        if (response.status === 204) return {} as T;
        return response.json() as Promise<T>;
    }

    if (response.status === 401 && !skipAuthRefresh) {
        if (!isRefreshing) {
            isRefreshing = true;
            try {
                const refreshResponse = await fetch(`${API_BASE_URL}/auth/refresh`, {
                    method: "POST",
                    credentials: 'include' as const,
                });

                if (!refreshResponse.ok) {
                    const errorPayload = await refreshResponse.json() as ApiErrorPayload;
                    throw new ApiClientError(refreshResponse.status, errorPayload);
                }

                const authData = await refreshResponse.json() as LoginResponse;

                // Call the new setAuth action
                setAuth({
                    user: authData.user!,
                    accessToken: authData.accessToken!,
                });
                processQueue(null, authData.accessToken);

                headers.set("Authorization", `Bearer ${authData.accessToken}`);
                const retryResponse = await fetch(url, { ...fetchOptions, headers });

                if (!retryResponse.ok) {
                    const errorPayload = await retryResponse.json() as ApiErrorPayload;
                    throw new ApiClientError(retryResponse.status, errorPayload);
                }
                if (retryResponse.status === 204) return {} as T;
                return retryResponse.json() as Promise<T>;

            } catch (error) {
                const clientError = error instanceof ApiClientError
                    ? error
                    : new ApiClientError(500, { error: (error as Error).message || "Token refresh failed" });

                processQueue(clientError, null);
                logout(); // Logout on refresh failure
                return Promise.reject(clientError);
            } finally {
                isRefreshing = false;
            }
        } else {
            return new Promise<T>((resolve, reject) => {
                failedQueue.push((newAccessToken: string | null) => {
                    if (newAccessToken) {
                        const newHeaders = new Headers(options.headers);
                        newHeaders.set("Authorization", `Bearer ${newAccessToken}`);
                        resolve(apiClient<T>(endpoint, { ...options, headers: newHeaders }));
                    } else {
                        reject(new ApiClientError(401, { error: 'Session refresh failed.' }));
                    }
                });
            });
        }
    }

    const errorPayload = await response.json() as ApiErrorPayload;
    return Promise.reject(new ApiClientError(response.status, errorPayload));
}

function createRequestHeaders(existingHeaders: HeadersInit | undefined): Headers {
    const headers = new Headers(existingHeaders);
    if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    return headers;
}

// Update method signatures to use ApiClientOptions
apiClient.get = <T>(url: string, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'GET' });
apiClient.post = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'POST', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });
apiClient.put = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'PUT', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });
apiClient.delete = <T>(url: string, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'DELETE' });
apiClient.deleteWithBody = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'DELETE', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });

export default apiClient;
'''
'''
// lib/api-client/errors.ts

export interface ApiErrorPayload {
    error: string;
    code?: string;
    details?: any; // For Zod validation errors
    issues?: string[]; // For password policy violations
    lockedUntil?: Date;
}

export class ApiClientError extends Error {
    public readonly status: number;
    public readonly payload: ApiErrorPayload;

    constructor(status: number, payload: ApiErrorPayload) {
        super(payload.error || 'An API error occurred');
        this.name = 'ApiClientError';
        this.status = status;
        this.payload = payload;
    }
}

/**
 * Type guard to check if an error is an instance of ApiClientError.
 * This is the correct way to check for our custom error on the client.
 */
export function isApiClientError(error: unknown): error is ApiClientError {
    return error instanceof ApiClientError;
}
'''
'''
// lib/api/docs.ts
import { OpenAPIHono } from '@hono/zod-openapi';
import { z } from 'zod';

export const app = new OpenAPIHono();

// Common schemas
export const ErrorSchema = z.object({
    error: z.string(),
    code: z.string().optional(),
    details: z.any().optional(),
});

export const SuccessSchema = z.object({
    message: z.string(),
    data: z.any().optional(),
});

// Authentication schemas
export const LoginRequestSchema = z.object({
    email: z.string().email(),
    password: z.string().min(8),
});

export const LoginResponseSchema = z.object({
    user: z.object({
        id: z.string(),
        email: z.string(),
        firstName: z.string(),
        lastName: z.string(),
        roles: z.array(z.string()),
    }),
    accessToken: z.string(),
    onboardingCompleted: z.boolean(),
});

export const MfaVerifyRequestSchema = z.object({
    code: z.string().length(6),
    mfaToken: z.string(),
});

// Register the documentation
app.doc('/doc', {
    openapi: '3.0.0',
    info: {
        version: '1.0.0',
        title: 'AWE e.V. API',
        description: 'Authentication API for AWE e.V. platform',
    },
    servers: [
        {
            url: 'https://api.awe-ev.org',
            description: 'Production server',
        },
        {
            url: 'http://localhost:3000',
            description: 'Development server',
        },
    ],
    components: {
        securitySchemes: {
            Bearer: {
                type: 'http',
                scheme: 'bearer',
            },
        },
    },
    tags: [
        {
            name: 'Authentication',
            description: 'Authentication endpoints',
        },
    ],
});
'''
'''
// lib/api/error-handler.client.ts
import { toast } from 'sonner';
import { ApiClientError, isApiClientError } from '@/lib/api-client/errors';

export function getErrorMessage(error: unknown): string {
    if (isApiClientError(error)) {
        return error.payload.error || 'An error occurred';
    }
    if (error instanceof Error) {
        return error.message;
    }
    return 'An unexpected error occurred';
}

export function getErrorCode(error: unknown): string | undefined {
    if (isApiClientError(error)) {
        return error.payload.code;
    }
    return undefined;
}

export function showErrorToast(error: unknown, fallbackMessage?: string): void {
    const message = getErrorMessage(error);
    toast.error(message || fallbackMessage || 'An error occurred');
}


export function isErrorType(error: unknown, code: string): boolean {
    return getErrorCode(error) === code;
}

export function showValidationErrors(error: unknown): void {
    if (isApiClientError(error) && error.payload.code === 'VALIDATION_ERROR' && error.payload.details?.fieldErrors) {
        const fieldErrors = error.payload.details.fieldErrors as Record<string, string[]>;
        Object.entries(fieldErrors).forEach(([field, errors]) => {
            errors.forEach((err) => {
                // Capitalize field name for better readability
                const formattedField = field.charAt(0).toUpperCase() + field.slice(1);
                toast.error(`${formattedField}: ${err}`);
            });
        });
    } else {
        showErrorToast(error, 'Validation failed. Please check your input.');
    }
}

export function showPasswordPolicyErrors(error: unknown): void {
    if (isApiClientError(error) && error.payload.code === 'PASSWORD_POLICY_VIOLATION' && error.payload.issues) {
        error.payload.issues.forEach((issue: string) => {
            toast.error(issue, { duration: 5000 });
        });
    } else {
        showErrorToast(error, 'Password does not meet the security requirements.');
    }
}

export function handleFormError(error: unknown): void {
    if (isApiClientError(error)) {
        switch (error.payload.code) {
            case 'VALIDATION_ERROR':
                showValidationErrors(error);
                break;
            case 'PASSWORD_POLICY_VIOLATION':
                showPasswordPolicyErrors(error);
                break;
            default:
                showErrorToast(error);
        }
    } else {
        showErrorToast(error, 'An unexpected error occurred.');
    }
}

export function isNetworkError(error: unknown): boolean {
    return !(error instanceof ApiClientError) && error instanceof TypeError;
}

export function isAuthenticationError(error: unknown): boolean {
    return isApiClientError(error) && error.status === 401;
}

export function isAuthorizationError(error: unknown): boolean {
    return isApiClientError(error) && error.status === 403;
}

export function isValidationError(error: unknown): boolean {
    return isErrorType(error, 'VALIDATION_ERROR');
}
'''
'''
// lib/api/error-handler.ts 
import { NextResponse } from 'next/server';
import { ZodError } from 'zod';
import {
    AuthError,
    InvalidCredentialsError,
    AccountExistsError,
    InvalidTokenError,
    MfaRequiredError,
    PasswordPolicyError,
    AccountLockedError
} from '@/lib/errors/auth.errors';
import { logger } from '@/lib/logger';

export class ApiError extends Error {
    constructor(
        public statusCode: number,
        public message: string,
        public code?: string,
        public details?: any
    ) {
        super(message);
        this.name = 'ApiError';
    }
}

export function handleApiError(error: unknown): NextResponse {
    // Log the error for debugging
    logger.error({ error }, 'API Error occurred');

    // Handle known error types
    if (error instanceof ZodError) {
        return NextResponse.json(
            {
                error: 'Validation failed',
                code: 'VALIDATION_ERROR',
                details: error.flatten(),
            },
            { status: 400 }
        );
    }

    if (error instanceof InvalidTokenError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'INVALID_TOKEN',
            },
            { status: 401 }
        );
    }

    if (error instanceof InvalidCredentialsError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'INVALID_CREDENTIALS',
            },
            { status: 401 }
        );
    }

    if (error instanceof AccountLockedError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'ACCOUNT_LOCKED',
                lockedUntil: error.lockedUntil,
            },
            { status: 423 }
        );
    }

    if (error instanceof PasswordPolicyError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'PASSWORD_POLICY_VIOLATION',
                issues: error.issues,
            },
            { status: 400 }
        );
    }

    if (error instanceof AccountExistsError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'ACCOUNT_EXISTS',
            },
            { status: 409 }
        );
    }

    if (error instanceof MfaRequiredError) {
        return NextResponse.json(
            {
                message: error.message,
                mfaRequired: true,
                mfaToken: error.mfaToken,
            },
            { status: 200 }
        );
    }

    if (error instanceof AuthError) {
        return NextResponse.json(
            {
                error: error.message,
                code: 'AUTH_ERROR',
            },
            { status: 403 }
        );
    }

    if (error instanceof ApiError) {
        return NextResponse.json(
            {
                error: error.message,
                code: error.code,
                details: error.details,
            },
            { status: error.statusCode }
        );
    }

    // Handle unknown errors
    return NextResponse.json(
        {
            error: 'An unexpected error occurred',
            code: 'INTERNAL_ERROR',
        },
        { status: 500 }
    );
}

export interface ErrorPayload {
    error: string;
    code?: 'VALIDATION_ERROR' | 'INVALID_TOKEN' | 'INVALID_CREDENTIALS' | 'ACCOUNT_LOCKED' | 'PASSWORD_POLICY_VIOLATION' | 'ACCOUNT_EXISTS' | 'AUTH_ERROR' | 'INTERNAL_ERROR';
    details?: any; // For Zod errors
    lockedUntil?: string; // Will be an ISO date string
    issues?: string[]; // For password policy errors
}

export interface ApiError {
    response?: {
        data?: ErrorPayload;
    };
}

export function isApiError(error: unknown): error is ApiError {
    return (
        typeof error === 'object' &&
        error !== null &&
        'response' in error &&
        typeof (error as any).response === 'object' &&
        (error as any).response !== null &&
        'data' in (error as any).response &&
        typeof (error as any).response.data === 'object'
    );
}
'''
'''
// lib/api/security-middleware.ts
import { NextRequest, NextResponse } from 'next/server';

export function addSecurityHeaders(response: NextResponse): NextResponse {
    // Security headers
    response.headers.set('X-Content-Type-Options', 'nosniff');
    response.headers.set('X-Frame-Options', 'DENY');
    response.headers.set('X-XSS-Protection', '1; mode=block');
    response.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    response.headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

    // CORS headers for API
    response.headers.set('Access-Control-Allow-Origin', process.env.NODE_ENV === 'production'
        ? 'https://awe-ev.org'
        : '*');
    response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    response.headers.set('Access-Control-Allow-Credentials', 'true');
    response.headers.set('Access-Control-Max-Age', '86400'); // 24 hours

    return response;
}

export function handleOptions(request: NextRequest): NextResponse | null {
    if (request.method === 'OPTIONS') {
        const response = new NextResponse(null, { status: 200 });
        return addSecurityHeaders(response);
    }
    return null;
}
'''
'''
// lib/api-handler.ts
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';
import { verifyAccessToken } from '@/lib/services/auth/jwt.service';
import type { AccessTokenPayload } from '@/types/auth.types';
import { consumeLogin, consumeGlobal } from '@/lib/services/rate-limit';
import { getIpFromRequest } from '@/lib/request';
import { auditService } from '@/lib/services/audit.service';
import {
    AuthError,
    InvalidTokenError,
} from '@/lib/errors/auth.errors';
import { ADMIN_ROLES } from '@/lib/helpers/roles';
import type { Role } from '@prisma/client';
import { hasPermission } from '@/lib/utils/permissions.utils';
import { type PermissionString } from '@/lib/audit/actions';
import * as Sentry from '@sentry/nextjs';
import { logger } from '@/lib/logger';
import { addSecurityHeaders, handleOptions } from '@/lib/api/security-middleware';
import { handleApiError } from '@/lib/api/error-handler';

type LimiterType = 'global' | 'auth' | 'passwordReset' | 'strict' | 'none';

type AuthOptions =
    | { level: 'public' }
    | {
        level: 'authenticated';
        allowedRoles?: readonly Role[];
        permission?: PermissionString;
    }
    | {
        level: 'admin';
        allowedRoles?: readonly Role[];
        permission?: PermissionString;
    };

interface HandlerOptions<TBody, TQuery> {
    auth?: AuthOptions;
    limiter?: LimiterType;
    bodySchema?: z.ZodSchema<TBody>;
    querySchema?: z.ZodSchema<TQuery>;
    description?: string;
    summary?: string;
    tags?: string[];
}

type ApiHandlerContext<
    TBody,
    TQuery,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
> = {
    params: TParams;
    session: AccessTokenPayload;
    body: TBody;
    query: TQuery;
};

type ApiHandler<
    TBody = unknown,
    TQuery = unknown,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
> = (
    req: NextRequest,
    context: ApiHandlerContext<TBody, TQuery, TParams>
) => Promise<NextResponse>;

async function getSessionFromRequest(req: NextRequest): Promise<AccessTokenPayload | null> {
    const authHeader = req.headers.get("authorization");
    if (!authHeader?.startsWith("Bearer ")) {
        return null;
    }

    try {
        const token = authHeader.substring(7);
        return await verifyAccessToken(token);
    } catch {
        return null;
    }
}

export function createApiHandler<
    TBody = unknown,
    TQuery = unknown,
    TParams extends Record<string, string | string[]> = Record<string, string | string[]>
>(
    handler: ApiHandler<TBody, TQuery, TParams>,
    options: HandlerOptions<TBody, TQuery> = {}
) {
    const {
        auth = { level: "public" },
        limiter: limiterType = "global",
        bodySchema,
        querySchema,
        description,
        summary,
        tags = ["API"],
    } = options;

    return async (req: NextRequest, context: { params: TParams }) => {
        // Handle OPTIONS requests for CORS
        const optionsResponse = handleOptions(req);
        if (optionsResponse) return optionsResponse;

        let session: AccessTokenPayload | null = null;
        const requestId = req.headers.get('x-request-id') || crypto.randomUUID();

        // Create response headers
        const responseHeaders = new Headers();
        responseHeaders.set('x-request-id', requestId);

        try {
            const ip = getIpFromRequest(req);

            // Rate limiting using your implementation
            if (limiterType !== "none" && ip) {
                let rateLimitResult;

                if (limiterType === "auth") {
                    rateLimitResult = await consumeLogin(ip);
                } else {
                    rateLimitResult = await consumeGlobal(ip);
                }

                if (!rateLimitResult.allowed) {
                    auditService.fromRequest(req, "api:rate_limit_exceeded" as PermissionString, null, {
                        limiter: limiterType,
                        ip,
                    });

                    const response = NextResponse.json({
                        error: "Too many requests.",
                        code: 'RATE_LIMIT_EXCEEDED',
                        retryAfter: rateLimitResult.retryAfterSeconds
                    }, { status: 429 });

                    response.headers.set('Retry-After', rateLimitResult.retryAfterSeconds.toString());
                    return addSecurityHeaders(response);
                }
            }

            session = await getSessionFromRequest(req);

            // Authentication checks
            if (auth.level === "authenticated" || auth.level === "admin") {
                if (!session) {
                    throw new InvalidTokenError("Authentication required. Please log in.");
                }

                if (auth.level === "admin" && !ADMIN_ROLES.some((role) => session!.roles.includes(role))) {
                    throw new AuthError("Forbidden: Administrator access is required for this resource.");
                }

                if (
                    auth.allowedRoles?.length &&
                    !auth.allowedRoles.some((role) => session!.roles.includes(role))
                ) {
                    throw new AuthError(
                        `Forbidden: Requires one of the following roles: ${auth.allowedRoles.join(", ")}`
                    );
                }

                if (auth.permission) {
                    const userPermissions = new Set<PermissionString>(
                        (session.permissions as PermissionString[]) || []
                    );
                    if (!hasPermission(userPermissions, auth.permission)) {
                        throw new AuthError(
                            `Forbidden: You do not have the required permission ('${auth.permission}') for this action.`
                        );
                    }
                }
            }

            // Parse query parameters
            let query: TQuery = {} as TQuery;
            if (querySchema) {
                const searchParams = Object.fromEntries(req.nextUrl.searchParams);
                query = await querySchema.parseAsync(searchParams);
            }

            // Parse request body
            let body: TBody = {} as TBody;
            if (req.method !== "GET" && req.method !== "DELETE" && bodySchema) {
                const reqJson = await req.json();
                body = await bodySchema.parseAsync(reqJson);
            }

            // Execute the handler
            const result = await handler(req, { ...context, session: session!, body, query });

            // Add security headers to response
            if (result instanceof Response) {
                return addSecurityHeaders(result);
            }

            return result;

        } catch (error: unknown) {
            const actorId = session?.sub;

            // Log the error
            logger.error({
                error: error instanceof Error ? error.message : String(error),
                stack: error instanceof Error ? error.stack : undefined,
                requestId,
                url: req.url,
                method: req.method,
                actorId
            }, '[API ERROR] Exception in API handler');

            // Send to Sentry in production
            if (process.env.NODE_ENV === 'production') {
                Sentry.captureException(error, {
                    extra: {
                        requestId,
                        url: req.url,
                        method: req.method,
                        actorId
                    },
                    tags: {
                        module: "ApiHandler",
                        endpoint: req.url
                    }
                });
            }

            // Handle specific error types
            return handleApiError(error);
        }
    };
}
'''
'''
// lib/i18n.ts
import { getRequestConfig } from 'next-intl/server';

export const locales = ['en', 'de', 'fr'] as const;
export type Locale = (typeof locales)[number];
export const defaultLocale: Locale = 'en';

import enMessages from '@/messages/en.json';
import deMessages from '@/messages/de.json';
import frMessages from '@/messages/fr.json';

export type Messages = typeof enMessages;

const allTranslations: Record<Locale, Messages> = {
  en: enMessages,
  de: deMessages as unknown as Messages,
  fr: frMessages as unknown as Messages,
};

export const localeNames = {
  en: 'English',
  de: 'Deutsch',
  fr: 'Français',
} as const;

export const localeFlags = {
  en: '🇺🇸',
  de: '🇩🇪',
  fr: '🇫🇷',
} as const;

export function getTranslations(locale: Locale): Messages {
  return allTranslations[locale] ?? allTranslations.en;
}

export default getRequestConfig(async ({ locale }) => {
  const validLocale = locales.includes(locale as Locale) ? (locale as Locale) : defaultLocale;

  return {
    locale: validLocale,
    messages: getTranslations(validLocale),
  };
});
'''
'''
// lib/logger.ts

import pino from 'pino';

let logger: pino.Logger;

const isDev = process.env.NODE_ENV === 'development';
const usePretty = process.env.LOG_PRETTY === 'true';

if (isDev && usePretty) {
    console.log('✅ Initializing pino-pretty logger for development...');
    logger = pino({
        level: 'debug',
        transport: {
            target: 'pino-pretty',
            options: {
                colorize: true,
                translateTime: 'SYS:standard',
                ignore: 'pid,hostname',
            },
        },
    });
} else {
    logger = pino({
        level: process.env.LOG_LEVEL || 'info',
    });
}

export { logger };
'''
'''
import { PostHog } from "posthog-node";

export const posthog =
  process.env.POSTHOG_KEY
    ? new PostHog(process.env.POSTHOG_KEY, {
        host: process.env.POSTHOG_HOST || "https://app.posthog.com",
      })
    : null;

'''
'''
// lib/request.ts
import { NextRequest } from 'next/server';
import { match } from '@formatjs/intl-localematcher';
import Negotiator from 'negotiator';
import { defaultLocale, locales } from '@/lib/i18n';

export function getLocaleFromRequest(request: NextRequest): string {
  const negotiatorHeaders: Record<string, string> = {};
  request.headers.forEach((value, key) => (negotiatorHeaders[key] = value));

  const languages = new Negotiator({ headers: negotiatorHeaders }).languages();

  try {
    return match(languages, locales, defaultLocale);
  } catch {
    return defaultLocale;
  }
}


export function getIpFromRequest(request: NextRequest): string | undefined {
  const xff = request.headers.get('x-forwarded-for');
  if (xff) {
    return xff.split(',')[0].trim();
  }
  return "127.0.0.1";
}
'''
'''
// stores/auth.store.ts
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { AuthUser, LoginResponse } from '@/types/auth.types';
import { apiClient } from '@/lib/api-client/base';
import { isApiError } from '@/lib/api/error-handler';

interface AuthState {
    // State
    user: AuthUser | null;
    accessToken: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    deviceVerificationRequired: boolean;
    deviceId: string | null;
    mfaRequired: boolean;
    mfaToken: string | null;
    loginError: string | null;
    mfaError: string | null;

    // Actions
    setAuth: (data: { user: AuthUser; accessToken: string }) => void;
    login: (email: string, password: string, rememberMe?: boolean) => Promise<{ success: boolean; error?: string }>;
    loginWithMfa: (code: string, mfaToken: string) => Promise<{ success: boolean; error?: string }>;
    verifyDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
    register: (email: string, password: string, confirmPassword: string) => Promise<{ success: boolean; error?: string; issues?: string[]; requiresVerification?: boolean }>;
    logout: () => Promise<void>;
    refreshAccessToken: () => Promise<void>;
    changePassword: (currentPassword: string, newPassword: string, confirmPassword: string) => Promise<{ success: boolean; error?: string; issues?: string[] }>;
    fetchUser: () => Promise<void>;
    clearAuth: () => void;

    // OAuth
    loginWithGoogle: (code: string, redirectUri: string) => Promise<{ success: boolean; error?: string }>;
    loginWithFacebook: (code: string, redirectUri: string) => Promise<{ success: boolean; error?: string }>;

    // Device Management
    getDevices: () => Promise<any[]>;
    trustDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
    revokeDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            // Initial state
            user: null,
            accessToken: null,
            isAuthenticated: false,
            isLoading: false,
            deviceVerificationRequired: false,
            deviceId: null,
            mfaRequired: false,
            mfaToken: null,
            loginError: null,
            mfaError: null,

            setAuth: (data: { user: AuthUser; accessToken: string }) => {
                set({
                    user: data.user,
                    accessToken: data.accessToken,
                    isAuthenticated: true,
                    isLoading: false,
                    // Reset flow states
                    deviceVerificationRequired: false,
                    deviceId: null,
                    mfaRequired: false,
                    mfaToken: null,
                    loginError: null,
                });
            },

            // Login with email and password
            login: async (email: string, password: string, rememberMe = false) => {
                set({ isLoading: true, loginError: null });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/login', {
                        email,
                        password,
                        rememberMe
                    });

                    // Handle different response types
                    if (response.mfaRequired) {
                        set({
                            mfaRequired: true,
                            mfaToken: response.mfaToken,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    // Successful login
                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null,
                        mfaRequired: false,
                        mfaToken: null,
                        loginError: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Login failed';

                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        switch (errorData.code) {
                            case 'ACCOUNT_LOCKED':
                                errorMessage = `Account locked. Try again after ${new Date(errorData.lockedUntil!).toLocaleString()}`;
                                break;
                            case 'INVALID_CREDENTIALS':
                                errorMessage = 'Invalid email or password';
                                break;
                            case 'VALIDATION_ERROR':
                                errorMessage = 'Please check your email and password';
                                break;
                            default:
                                errorMessage = errorData.error || 'An unknown login error occurred';
                        }
                    } else {
                        errorMessage = 'Network error occurred. Please try again';
                    }

                    set({ isLoading: false, loginError: errorMessage });
                    return { success: false, error: errorMessage };
                }
            },

            // Login with MFA
            loginWithMfa: async (code: string, mfaToken: string) => {
                set({ isLoading: true, mfaError: null });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/mfa/verify', {
                        code,
                        mfaToken
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        mfaRequired: false,
                        mfaToken: null,
                        mfaError: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'MFA verification failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false, mfaError: errorMessage });
                    return { success: false, error: errorMessage };
                }
            },

            // Verify device
            verifyDevice: async (deviceId: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/verify-device', {
                        deviceId
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Device verification failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // Register new user
            register: async (email: string, password: string, confirmPassword: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<{ requiresVerification: boolean }>('/auth/register', {
                        email,
                        password,
                        confirmPassword
                    });

                    set({ isLoading: false });

                    return {
                        success: true,
                        requiresVerification: response.requiresVerification
                    };
                } catch (error: unknown) {
                    set({ isLoading: false });

                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        if (errorData.code === 'PASSWORD_POLICY_VIOLATION') {
                            return {
                                success: false,
                                error: errorData.error,
                                issues: errorData.issues,
                            };
                        }

                        return {
                            success: false,
                            error: errorData.error || 'Registration failed',
                        };
                    }

                    return {
                        success: false,
                        error: 'Network error occurred during registration',
                    };
                }
            },

            // Logout
            logout: async () => {
                try {
                    await apiClient.post('/auth/logout', undefined, { skipAuthRefresh: true });
                } catch (error) {
                    console.error('Logout error:', error);
                } finally {
                    get().clearAuth();
                }
            },

            // Refresh access token
            refreshAccessToken: async () => {
                try {
                    const response = await apiClient.post<LoginResponse>('/auth/refresh', undefined, {
                        skipAuthRefresh: true
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true
                    });
                } catch (error) {
                    get().clearAuth();
                    throw error;
                }
            },

            // Change password
            changePassword: async (currentPassword: string, newPassword: string, confirmPassword: string) => {
                try {
                    await apiClient.post('/auth/change-password', {
                        currentPassword,
                        newPassword,
                        confirmPassword
                    });

                    return { success: true };
                } catch (error: unknown) {
                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        if (errorData.code === 'PASSWORD_POLICY_VIOLATION') {
                            return {
                                success: false,
                                error: errorData.error,
                                issues: errorData.issues
                            };
                        }

                        return {
                            success: false,
                            error: errorData.error || 'Password change failed'
                        };
                    }

                    return {
                        success: false,
                        error: 'Network error occurred'
                    };
                }
            },

            // Fetch current user
            fetchUser: async () => {
                try {
                    const response = await apiClient.get<{ user: AuthUser }>('/auth/me');

                    set({
                        user: response.user,
                        isAuthenticated: true
                    });
                } catch (error) {
                    get().clearAuth();
                }
            },

            // Clear auth state
            clearAuth: () => {
                set({
                    user: null,
                    accessToken: null,
                    isAuthenticated: false,
                    isLoading: false,
                    deviceVerificationRequired: false,
                    deviceId: null,
                    mfaRequired: false,
                    mfaToken: null,
                    loginError: null,
                    mfaError: null
                });
            },

            // OAuth login with Google
            loginWithGoogle: async (code: string, redirectUri: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/oauth/google', {
                        code,
                        redirectUri
                    });

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Google login failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // OAuth login with Facebook
            loginWithFacebook: async (code: string, redirectUri: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/oauth/facebook', {
                        code,
                        redirectUri
                    });

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Facebook login failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // Get user devices
            getDevices: async () => {
                try {
                    const response = await apiClient.get<{ devices: any[] }>('/auth/devices');
                    return response.devices;
                } catch (error) {
                    console.error('Failed to fetch devices:', error);
                    return [];
                }
            },

            // Trust a device
            trustDevice: async (deviceId: string) => {
                try {
                    await apiClient.post('/auth/devices', { deviceId });
                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Failed to trust device';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    return { success: false, error: errorMessage };
                }
            },

            // Revoke a device
            revokeDevice: async (deviceId: string) => {
                try {
                    await apiClient.deleteWithBody('/auth/devices', { deviceId });
                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Failed to revoke device';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    return { success: false, error: errorMessage };
                }
            }
        }),
        {
            name: 'auth-storage',
            storage: createJSONStorage(() => localStorage),
            partialize: (state) => ({
                user: state.user,
                accessToken: state.accessToken,
                isAuthenticated: state.isAuthenticated
            })
        }
    )
);
'''
'''
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

'''
'''
// app/api/auth/[...nextauth]/route.ts
import { NextRequest, NextResponse } from 'next/server';
import { auth } from '@/lib/auth/lucia';

export async function POST(req: NextRequest) {
    return auth.handler(req);
}

export async function GET(req: NextRequest) {
    return auth.handler(req);
}
'''
'''
// app/api/v1/auth/change-password/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { PasswordPolicyError } from '@/lib/errors/auth.errors';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const changePasswordSchema = z.object({
    currentPassword: z.string().min(1, "Current password is required"),
    newPassword: z.string().min(8, "New password must be at least 8 characters"),
    confirmPassword: z.string().min(1, "Password confirmation is required"),
}).refine((data) => data.newPassword === data.confirmPassword, {
    message: "Passwords don't match",
    path: ["confirmPassword"],
});

export const POST = createApiHandler(
    async (req, { session, body: { currentPassword, newPassword } }) => {
        try {
            const ip = getIpFromRequest(req);
            const userAgent = req.headers.get('user-agent') || undefined;

            await authService.changePassword(
                session.sub,
                currentPassword,
                newPassword,
                ip,
                userAgent
            );

            return NextResponse.json({
                message: 'Password changed successfully',
                success: true
            });
        } catch (error) {
            if (error instanceof PasswordPolicyError) {
                return NextResponse.json({
                    error: error.message,
                    code: 'PASSWORD_POLICY_VIOLATION',
                    issues: error.issues,
                }, { status: 400 });
            }

            if (error instanceof Error && error.name === 'AuthError') {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_CURRENT_PASSWORD',
                }, { status: 400 });
            }


            throw error;
        }
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: changePasswordSchema,
        summary: 'Change password',
        description: 'Changes the user password',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/check-email/route.ts
import { prisma } from '@/lib/db';
import { z } from 'zod';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';

const emailCheckSchema = z.object({
    email: z.string().email('A valid email is required.'),
});

export const POST = createApiHandler(
    async (req, { body: { email } }) => {
        const user = await prisma.user.findFirst({
            where: {
                email: {
                    equals: email,
                    mode: 'insensitive',
                },
                isVerified: true,
            },
        });

        return NextResponse.json({
            available: !user,
            message: !user ? 'Email is available' : 'Email is already taken'
        });
    },
    {
        limiter: 'global',
        bodySchema: emailCheckSchema,
        summary: 'Check email availability',
        description: 'Checks if an email address is available for registration',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/devices/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const trustDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
});

const revokeDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
});

// GET - List user devices
export const GET = createApiHandler(
    async (req, { session }) => {
        const devices = await deviceManagementService.getUserDevices(session.sub);

        return NextResponse.json({
            devices,
            count: devices.length,
        });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'List user devices',
        description: 'Returns a list of devices associated with the user account',
        tags: ['Authentication', 'Device Management'],
    }
);

// POST - Trust a device
export const POST = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        await deviceManagementService.trustDevice(session.sub, deviceId);

        return NextResponse.json({
            message: 'Device trusted successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: trustDeviceSchema,
        summary: 'Trust device',
        description: 'Marks a device as trusted for future logins',
        tags: ['Authentication', 'Device Management'],
    }
);

// DELETE - Revoke a device
export const DELETE = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        await deviceManagementService.revokeDevice(session.sub, deviceId);

        return NextResponse.json({
            message: 'Device revoked successfully',
            success: true
        });
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: revokeDeviceSchema,
        summary: 'Revoke device',
        description: 'Revokes trust from a device',
        tags: ['Authentication', 'Device Management'],
    }
);
'''
'''
// app/api/v1/auth/email-status/route.ts
import { NextResponse } from 'next/server';
import { z } from 'zod';
import { prisma } from '@/lib/db';
import { createApiHandler } from '@/lib/api-handler';

const querySchema = z.object({
    email: z.string().email(),
});

type VerificationStatus = 'VERIFIED' | 'UNVERIFIED' | 'NOT_FOUND';

export const GET = createApiHandler(
    async (req, { query }) => {
        const { email } = query;

        const user = await prisma.user.findUnique({
            where: { email: email.toLowerCase() },
            select: { isVerified: true },
        });

        let status: VerificationStatus;

        if (!user) {
            status = 'NOT_FOUND';
        } else if (user.isVerified) {
            status = 'VERIFIED';
        } else {
            status = 'UNVERIFIED';
        }

        return NextResponse.json({
            status,
            message: status === 'VERIFIED' ? 'Email is verified' :
                status === 'UNVERIFIED' ? 'Email is not verified' :
                    'Email not found in system'
        });
    },
    {
        limiter: 'strict',
        querySchema,
        summary: 'Check email verification status',
        description: 'Checks the verification status of an email address',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/login/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { loginSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const loginResponseSchema = z.object({
    user: z.object({
        id: z.string(),
        email: z.string(),
        firstName: z.string(),
        lastName: z.string(),
        roles: z.array(z.string()),
        permissions: z.array(z.string()),
        onboardingCompleted: z.boolean(),
    }),
    accessToken: z.string(),
    mfaRequired: z.boolean().optional(),
    mfaToken: z.string().optional(),
    deviceVerificationRequired: z.boolean().optional(),
    deviceId: z.string().optional(),
});

export const POST = createApiHandler(
    async (req, { body: { email, password } }) => {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get('user-agent') || undefined;

        // Parse device information
        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const result = await authService.loginWithPassword(email, password, ip, userAgent, deviceInfo);

        if ('mfaRequired' in result) {
            return NextResponse.json({
                mfaRequired: true,
                mfaToken: result.mfaToken,
            });
        }

        if ('deviceVerificationRequired' in result) {
            return NextResponse.json({
                deviceVerificationRequired: true,
                deviceId: result.deviceId,
            });
        }

        const { authResponse, refreshToken } = result;

        const response = NextResponse.json({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
            deviceInfo: deviceInfo,
        });

        response.cookies.set(createSessionCookie(refreshToken));
        return response;
    },
    {
        limiter: 'auth',
        bodySchema: loginSchema,
        summary: 'User login',
        description: 'Authenticates a user with email and password',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/logout/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { AUTH_CONFIG } from '@/lib/config/auth.config';
import { authService } from '@/lib/services/auth/auth.service';
import { clearSessionCookie } from '@/lib/services/auth/cookie.service';
import { NextResponse } from 'next/server';

export const POST = createApiHandler(
    async (req) => {
        const refreshTokenFromCookie = req.cookies.get(AUTH_CONFIG.SESSION_COOKIE_NAME)?.value;

        if (refreshTokenFromCookie) {
            await authService.logout(refreshTokenFromCookie);
        }

        const response = NextResponse.json({
            message: 'Logged out successfully.',
            success: true
        });

        response.cookies.set(clearSessionCookie());
        return response;
    },
    {
        auth: { level: 'authenticated' },
        summary: 'User logout',
        description: 'Logs out the current user and clears the session',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/me/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';

export const GET = createApiHandler(
    async (_req, { session }) => {
        const user = await authService.getUserById(session!.sub);

        if (!user) {
            return NextResponse.json({
                error: "User not found.",
                code: 'USER_NOT_FOUND'
            }, { status: 404 });
        }

        return NextResponse.json({
            user,
            session: {
                sub: session!.sub,
                email: session!.email,
                roles: session!.roles,
                permissions: session!.permissions,
                isImpersonating: session!.isImpersonating,
                actAsSub: session!.actAsSub,
            }
        });
    },
    {
        auth: { level: 'authenticated' },
        summary: 'Get current user',
        description: 'Returns the current authenticated user information',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/mfa/verify/route.ts 
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { mfaVerifySchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { verifyMfaToken } from '@/lib/services/auth/jwt.service';
import { NextResponse } from 'next/server';


export const POST = createApiHandler(
    async (req, { body: { code, mfaToken } }) => {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get("user-agent") || undefined;

        const payload = await verifyMfaToken(mfaToken);

        const { authResponse, refreshToken } = await authService.verifyMfaAndLogin(payload.sub, code, ip, userAgent);

        const response = NextResponse.json({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
        });

        response.cookies.set(createSessionCookie(refreshToken));
        return response;
    },
    {
        limiter: 'auth',
        bodySchema: mfaVerifySchema,
        summary: 'Verify MFA code',
        description: 'Verifies a multi-factor authentication code',
        tags: ['Authentication', 'MFA'],
    }
);
'''
'''
// app/api/v1/auth/oauth/facebook/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { oauthInitiateSchema } from '@/lib/schemas/auth.schemas';
import { auditService } from '@/lib/services/audit.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { exchangeFacebookCode, getFacebookUserInfo, oauthService } from '@/lib/services/auth/oauth.service';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const facebookCallbackQuerySchema = z.object({
    code: z.string().optional(),
    state: z.string().optional(),
    error: z.string().optional(),
});

// GET - OAuth Callback
export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const { code, state, error } = facebookCallbackQuerySchema.parse(Object.fromEntries(searchParams));

    const ip = getIpFromRequest(request);
    const userAgent = request.headers.get('user-agent');

    if (error) {
        auditService.fromRequest(request, 'oauth_error', null, { provider: 'facebook', error, ip, userAgent });
        return NextResponse.redirect(new URL(`/login?error=oauth_access_denied`, request.url));
    }

    if (!code) {
        auditService.fromRequest(request, 'oauth_missing_code', null, { provider: 'facebook', ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_invalid_response', request.url));
    }

    try {
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/facebook`;
        const { access_token } = await exchangeFacebookCode(code, redirectUri);
        const userInfo = await getFacebookUserInfo(access_token);

        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const normalizedData = {
            email: userInfo.email,
            firstName: userInfo.first_name,
            lastName: userInfo.last_name,
            avatarUrl: userInfo.picture.data.url,
        };

        const { authResponse, refreshToken } = await oauthService.handleLogin('facebook', normalizedData, deviceInfo, ip, userAgent ?? undefined);
        auditService.fromRequest(request, 'oauth_login_success', authResponse.user.id, { provider: 'facebook' });

        const response = NextResponse.redirect(new URL(state ? decodeURIComponent(state) : '/dashboard', request.url));
        response.cookies.set(createSessionCookie(refreshToken));
        return response;
    } catch (err) {
        console.error('Facebook OAuth Callback Error:', err);
        auditService.fromRequest(request, 'oauth_exchange_failed', null, { provider: 'facebook', error: String(err), ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_failed', request.url));
    }
}

// POST - Initiate OAuth
export const POST = createApiHandler(
    async (req, { body }) => {
        const { returnTo } = body;

        const clientId = process.env.FACEBOOK_APP_ID;
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/facebook`;

        if (!clientId) {
            auditService.fromRequest(req, 'oauth_config_error', null, { provider: 'facebook', reason: 'FACEBOOK_APP_ID is not configured' });
            throw new Error('OAuth provider is not configured.');
        }

        const authUrl = new URL('https://www.facebook.com/v18.0/dialog/oauth');
        authUrl.searchParams.set('client_id', clientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'email public_profile');

        if (body.returnTo) {
            authUrl.searchParams.set('state', encodeURIComponent(body.returnTo));
        }

        return NextResponse.json({
            url: authUrl.toString(),
            provider: 'facebook'
        });
    },
    {
        limiter: 'global',
        bodySchema: oauthInitiateSchema,
        summary: 'Initiate Facebook OAuth',
        description: 'Starts the Facebook OAuth flow',
        tags: ['Authentication', 'OAuth'],
    }
);
'''
'''
// app/api/v1/auth/oauth/google/route.ts (Updated)
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { oauthInitiateSchema } from '@/lib/schemas/auth.schemas';
import { auditService } from '@/lib/services/audit.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { exchangeGoogleCode, getGoogleUserInfo, oauthService } from '@/lib/services/auth/oauth.service';
import { NextRequest, NextResponse } from 'next/server';
import { z } from 'zod';

const googleCallbackQuerySchema = z.object({
    code: z.string().optional(),
    state: z.string().optional(),
    error: z.string().optional(),
});

// GET - OAuth Callback
export async function GET(request: NextRequest) {
    const { searchParams } = new URL(request.url);
    const { code, state, error } = googleCallbackQuerySchema.parse(Object.fromEntries(searchParams));

    const ip = getIpFromRequest(request);
    const userAgent = request.headers.get('user-agent');

    if (error) {
        auditService.fromRequest(request, 'oauth_error', null, { provider: 'google', error, ip, userAgent });
        return NextResponse.redirect(new URL(`/login?error=oauth_access_denied`, request.url));
    }

    if (!code) {
        auditService.fromRequest(request, 'oauth_missing_code', null, { provider: 'google', ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_invalid_response', request.url));
    }

    try {
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/google`;
        const { access_token } = await exchangeGoogleCode(code, redirectUri);
        const userInfo = await getGoogleUserInfo(access_token);

        // Parse device information
        const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

        const normalizedData = {
            email: userInfo.email,
            firstName: userInfo.given_name,
            lastName: userInfo.family_name,
            avatarUrl: userInfo.picture,
        };

        const result = await oauthService.handleLogin('google', normalizedData, deviceInfo, ip, userAgent ?? undefined);
        auditService.fromRequest(request, 'oauth_login_success', result.authResponse.user.id, { provider: 'google' });

        const response = NextResponse.redirect(new URL(state ? decodeURIComponent(state) : '/dashboard', request.url));
        response.cookies.set(createSessionCookie(result.refreshToken));
        return response;

    } catch (err) {
        console.error('Google OAuth Callback Error:', err);
        auditService.fromRequest(request, 'oauth_exchange_failed', null, { provider: 'google', error: String(err), ip, userAgent });
        return NextResponse.redirect(new URL('/login?error=oauth_failed', request.url));
    }
}

// POST - Initiate OAuth
export const POST = createApiHandler(
    async (req, { body }) => {
        const { returnTo } = body;
        const clientId = process.env.GOOGLE_CLIENT_ID;
        const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/oauth/google`;

        if (!clientId) {
            auditService.fromRequest(req, 'oauth_config_error', null, { provider: 'google', reason: 'GOOGLE_CLIENT_ID is not configured' });
            throw new Error('OAuth provider is not configured.');
        }

        const authUrl = new URL('https://accounts.google.com/o/oauth2/v2/auth');
        authUrl.searchParams.set('client_id', clientId);
        authUrl.searchParams.set('redirect_uri', redirectUri);
        authUrl.searchParams.set('response_type', 'code');
        authUrl.searchParams.set('scope', 'email profile');
        authUrl.searchParams.set('access_type', 'offline');
        authUrl.searchParams.set('prompt', 'consent');

        if (body.returnTo) {
            authUrl.searchParams.set('state', encodeURIComponent(body.returnTo));
        }

        return NextResponse.json({
            url: authUrl.toString(),
            provider: 'google'
        });
    },
    {
        limiter: 'global',
        bodySchema: oauthInitiateSchema,
        summary: 'Initiate Google OAuth',
        description: 'Starts the Google OAuth flow',
        tags: ['Authentication', 'OAuth'],
    }
);
'''
'''
// app/api/v1/auth/password-reset/confirm/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { passwordResetConfirmSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';
import { NextResponse } from 'next/server';


export const POST = createApiHandler(
    async (_req, { body: { token, newPassword } }) => {
        try {
            await authService.resetPassword(token, newPassword);
            return NextResponse.json({
                message: "Password has been reset successfully.",
                success: true
            });
        } catch (error) {
            if (error instanceof InvalidTokenError) {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_TOKEN'
                }, { status: 400 });
            }
            throw error;
        }
    },
    {
        limiter: 'strict',
        bodySchema: passwordResetConfirmSchema,
        summary: 'Confirm password reset',
        description: 'Resets a user password using a reset token',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/password-reset/request/route.ts
import { Locale } from '@/lib/i18n';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { getLocaleFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { auditService } from '@/lib/services/audit.service';
import { passwordResetRequestSchema } from '@/lib/schemas/auth.schemas';

export const POST = createApiHandler(
    async (req, { body: { email } }) => {
        const locale = getLocaleFromRequest(req) as Locale;

        // Service call is inside the handler, but we always return a success message
        // to prevent user enumeration.
        await authService.requestPasswordReset(email, locale);

        // Use the audit service to log the event
        auditService.fromRequest(req, AUDIT_ACTIONS.PASSWORD_RESET_REQUESTED, null, {
            locale,
            email: email.replace(/(.{2}).*(@.*)/, '$1***$2') // Partially mask email in logs
        });

        return NextResponse.json({
            message: "If an account with that email exists, a reset link has been sent.",
            success: true
        });
    },
    {
        limiter: 'passwordReset',
        bodySchema: passwordResetRequestSchema,
        summary: 'Request password reset',
        description: 'Sends a password reset email to the user',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/refresh/route.ts
import { createApiHandler } from '@/lib/api-handler';
import { AUTH_CONFIG } from '@/lib/config/auth.config';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { clearSessionCookie, createSessionCookie } from '@/lib/services/auth/cookie.service';
import { NextResponse } from 'next/server';

export const POST = createApiHandler(async (req) => {
    const refreshTokenFromCookie = req.cookies.get(AUTH_CONFIG.SESSION_COOKIE_NAME)?.value;

    if (!refreshTokenFromCookie) {
        throw new InvalidTokenError('Missing session token.');
    }

    try {
        const ip = getIpFromRequest(req);
        const userAgent = req.headers.get('user-agent') || undefined;

        const { authResponse, refreshToken: newRefreshToken } = await authService.refresh(refreshTokenFromCookie, ip, userAgent);

        const response = NextResponse.json({
            user: authResponse.user,
            accessToken: authResponse.accessToken,
            onboardingCompleted: authResponse.onboardingCompleted,
        });

        response.cookies.set(createSessionCookie(newRefreshToken));
        return response;

    } catch (error) {
        if (error instanceof InvalidTokenError) {
            const response = NextResponse.json({
                error: 'Session expired or invalid.',
                code: 'SESSION_EXPIRED'
            }, { status: 401 });

            response.cookies.set(clearSessionCookie());
            return response;
        }
        throw error;
    };
},
    {
        summary: 'Refresh access token',
        description: 'Refreshes the access token using a refresh token',
        tags: ['Authentication'],
    });
'''
'''
// app/api/v1/auth/register/route.ts (Updated)

import { createApiHandler } from '@/lib/api-handler';
import { AccountExistsUnverifiedError, AccountExistsVerifiedError, PasswordPolicyError } from '@/lib/errors/auth.errors';
import type { Locale } from '@/lib/i18n';
import { getIpFromRequest, getLocaleFromRequest } from '@/lib/request';
import { signUpSchema } from '@/lib/schemas/auth.schemas';
import { authService } from '@/lib/services/auth/auth.service';

import { NextResponse } from 'next/server';

export const POST = createApiHandler(
    async (req, { body: credentials }) => {
        try {
            const ip = getIpFromRequest(req);
            const locale = getLocaleFromRequest(req) as Locale;

            await authService.register(credentials, ip, locale);

            return NextResponse.json({
                message: 'Registration successful. Please check your email.',
                requiresVerification: true,
            },
                { status: 201 }
            );
        } catch (error) {
            if (error instanceof AccountExistsUnverifiedError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'ACCOUNT_EXISTS_UNVERIFIED',
                    requiresVerification: true,
                },
                    { status: 200 }
                );
            }
            if (error instanceof AccountExistsVerifiedError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'ACCOUNT_EXISTS_VERIFIED',
                    requiresVerification: false,
                },
                    { status: 409 }
                );
            }
            if (error instanceof PasswordPolicyError) {
                return NextResponse.json({
                    message: error.message,
                    code: 'PASSWORD_POLICY_VIOLATION',
                    issues: error.issues,
                },
                    { status: 400 }
                );
            }
            throw error;
        }
    },
    {
        limiter: 'auth',
        bodySchema: signUpSchema,
        summary: 'User registration',
        description: 'Registers a new user account',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/resend-verification/route.ts
import { Locale } from '@/lib/i18n';
import { z } from 'zod';
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { getLocaleFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';

const resendVerificationSchema = z.object({
    email: z.string().email('Valid email is required'),
});

export const POST = createApiHandler(
    async (req, { body }) => {
        const locale = getLocaleFromRequest(req) as Locale;
        const { email } = body;

        await authService.resendVerificationEmail(email, locale);

        return NextResponse.json({
            message: 'If a matching account exists, a new verification email has been sent.',
            success: true
        });
    },
    {
        limiter: 'strict',
        bodySchema: resendVerificationSchema,
        summary: 'Resend verification email',
        description: 'Resends a verification email to the user',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/verify-device/route.ts (New)
import { createApiHandler } from '@/lib/api-handler';
import { getIpFromRequest } from '@/lib/request';
import { authService } from '@/lib/services/auth/auth.service';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';
import { deviceManagementService } from '@/lib/services/auth/device-management.service';
import { NextResponse } from 'next/server';
import { z } from 'zod';

const verifyDeviceSchema = z.object({
    deviceId: z.string().min(1, "Device ID is required"),
    code: z.string().optional(), // If email verification is required
});

export const POST = createApiHandler(
    async (req, { session, body: { deviceId } }) => {
        try {
            const ip = getIpFromRequest(req);
            const userAgent = req.headers.get('user-agent') || undefined;

            // Parse device information
            const deviceInfo = deviceManagementService.parseDeviceInfo(userAgent || '', ip || '');

            const result = await authService.verifyDeviceAndLogin(
                session.sub,
                deviceId,
                ip,
                userAgent,
                deviceInfo
            );

            const response = NextResponse.json({
                user: result.authResponse.user,
                accessToken: result.authResponse.accessToken,
                onboardingCompleted: result.authResponse.onboardingCompleted,
                deviceInfo: result.deviceInfo
            });

            response.cookies.set(createSessionCookie(result.refreshToken));
            return response;
        } catch (error) {
            if (error instanceof Error && error.name === 'AuthError') {
                return NextResponse.json({
                    error: error.message,
                    code: 'INVALID_DEVICE',
                }, { status: 400 });
            }

            throw error;
        }
    },
    {
        auth: { level: 'authenticated' },
        limiter: 'strict',
        bodySchema: verifyDeviceSchema,
        summary: 'Verify device',
        description: 'Verifies a new device and completes login',
        tags: ['Authentication', 'Device Management'],
    }
);
'''
'''
// app/api/v1/auth/verify-email/route.ts
import { NextResponse } from 'next/server';
import { createApiHandler } from '@/lib/api-handler';
import { z } from 'zod';
import { authService } from '@/lib/services/auth/auth.service';
import { InvalidTokenError } from '@/lib/errors/auth.errors';
import { createSessionCookie } from '@/lib/services/auth/cookie.service';

const verifyEmailSchema = z.object({
    token: z.string().min(1, 'Verification token is required'),
});

export const POST = createApiHandler(
    async (_req, { body: { token } }) => {
        try {
            const { authResponse, refreshToken } = await authService.verifyEmail(token);

            const response = NextResponse.json({
                message: 'Email verified successfully.',
                user: authResponse.user,
                accessToken: authResponse.accessToken,
                onboardingCompleted: authResponse.onboardingCompleted,
            });

            response.cookies.set(createSessionCookie(refreshToken));
            return response;
        } catch (error) {
            if (error instanceof InvalidTokenError) {
                return NextResponse.json(
                    {
                        error: error.message,
                        code: 'INVALID_TOKEN'
                    },
                    { status: 400 }
                );
            }
            throw error;
        }
    },
    {
        limiter: 'global',
        bodySchema: verifyEmailSchema,
        summary: 'Verify email address',
        description: 'Verifies a user email address using a verification token',
        tags: ['Authentication'],
    }
);
'''
'''
// app/api/v1/auth/route.ts
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
    return NextResponse.json({
        message: 'AWE e.V. Authentication API v1',
        version: '1.0.0',
        endpoints: {
            login: '/api/v1/auth/login',
            logout: '/api/v1/auth/logout',
            register: '/api/v1/auth/register',
            refresh: '/api/v1/auth/refresh',
            'verify-email': '/api/v1/auth/verify-email',
            'password-reset': '/api/v1/auth/password-reset',
            mfa: {
                verify: '/api/v1/auth/mfa/verify',
            },
            oauth: {
                google: '/api/v1/auth/oauth/google',
                facebook: '/api/v1/auth/oauth/facebook',
            },
        },
        documentation: '/api/v1/docs',
    });
}
'''
'''
// app/api/health/route.ts
import { NextResponse } from 'next/server';
import { prisma } from '@/lib/db';

export async function GET() {
    try {
        await prisma.$queryRaw`SELECT 1`;
        return NextResponse.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: '1.0.0',
        });
    } catch (error) {
        return NextResponse.json(
            {
                status: 'unhealthy',
                error: 'Database connection failed',
            },
            { status: 503 }
        );
    }
}

'''
'''
import { serve } from 'inngest/next';
import { inngest } from '@/inngest/client';
import { functions } from '@/inngest/functions';

export const { GET, POST, PUT } = serve({
    client: inngest,
    functions,
});

'''
What needs to be added, modified, changed or arranged as this should be production ready, secure, perfomat and scale

