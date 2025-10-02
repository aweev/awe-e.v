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