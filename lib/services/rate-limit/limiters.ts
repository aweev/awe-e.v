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