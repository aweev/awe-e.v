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