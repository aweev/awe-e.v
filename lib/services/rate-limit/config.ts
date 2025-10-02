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