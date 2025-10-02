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
import { hashTokenForDb } from "@/lib/utils/auth.utils";
import type { PermissionString } from "@/lib/audit/actions";
import { AUDIT_ACTIONS } from "@/lib/audit/actions";
import { featureFlagService } from "@/lib/services/feature-flags/feature-flag.service";
import { consumeLogin } from "@/lib/services/rate-limit";
import { accountLockingService, AccountLockedError } from "./account-locking.service";
import { passwordPolicyService, PasswordPolicyError } from "./password-policy.service";
import { deviceManagementService, DeviceInfo } from "./device-management.service";

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