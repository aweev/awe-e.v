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