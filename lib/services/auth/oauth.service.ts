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