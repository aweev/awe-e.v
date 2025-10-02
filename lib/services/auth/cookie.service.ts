// lib/services/auth/cookie.service.ts
import { AUTH_CONFIG } from "@/lib/config/auth.config";
import type { ResponseCookie } from "next/dist/compiled/@edge-runtime/cookies";

export function createSessionCookie(
  token: string,
  rememberMe: boolean = false
): ResponseCookie {
  const cookieOptions: ResponseCookie = {
    name: AUTH_CONFIG.SESSION_COOKIE_NAME,
    value: token,
    httpOnly: true,
    secure: AUTH_CONFIG.COOKIE_SECURE,
    path: '/',
    sameSite: 'lax',
  };

  if (rememberMe) {
    cookieOptions.maxAge = 60 * 60 * 24 * 30; // 30 days
  }
  // If rememberMe is false, omit maxAge to make it a session cookie

  return cookieOptions;
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