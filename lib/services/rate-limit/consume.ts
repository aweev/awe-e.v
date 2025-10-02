// lib/services/rate-limit/consume.ts
import { RateLimiterRes } from 'rate-limiter-flexible';
import { getLoginLimiter, getGlobalLimiter } from './limiters';
import { pino } from 'pino';

const logger = pino({ name: 'rate-limit' });

export type LimiterDecision = { allowed: true } | { allowed: false; retryAfterSeconds: number };

function rejectionToDecision(rej: unknown): LimiterDecision {
  if (rej instanceof RateLimiterRes) {
    const secs = Math.ceil(rej.msBeforeNext / 1000) || 1;
    return { allowed: false, retryAfterSeconds: secs };
  }
  logger.error({ err: rej }, 'Unexpected rate-limiter error');
  return { allowed: false, retryAfterSeconds: 60 };
}

export async function consumeLogin(key: string): Promise<LimiterDecision> {
  try {
    await getLoginLimiter().consume(key);
    return { allowed: true };
  } catch (rej) {
    return rejectionToDecision(rej);
  }
}

export async function consumeGlobal(key: string): Promise<LimiterDecision> {
  try {
    await getGlobalLimiter().consume(key);
    return { allowed: true };
  } catch (rej) {
    return rejectionToDecision(rej);
  }
}