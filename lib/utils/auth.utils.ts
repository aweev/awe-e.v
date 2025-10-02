// lib/auth/auth.utils.ts
import crypto from "crypto";

export function hashTokenForDb(token: string) {
  return crypto.createHash("sha256").update(token).digest("hex");
}

export function generateRandomToken(bytes = 48) {
  return crypto.randomBytes(bytes).toString("hex");
}
