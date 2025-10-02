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