// lib/services/rate-limit/redis.ts
import Redis from 'ioredis';
import { ENV } from './env';
import { pino } from 'pino';

const logger = pino({ name: 'redis' });

function createRedis(): Redis {
  const client = new Redis(ENV.REDIS_URL, {
    maxRetriesPerRequest: 3,
    lazyConnect: true,
  });

  client.on('error', (err) => logger.error({ err }, 'Redis client error'));
  client.on('connect', () => logger.info('Redis connected'));
  client.on('close', () => logger.warn('Redis connection closed'));
  return client;
}

let _redis: Redis | undefined;
export function getRedis(): Redis {
  if (!_redis) _redis = createRedis();
  return _redis;
}

export async function pingRedis(): Promise<boolean> {
  try {
    return (await getRedis().ping()) === 'PONG';
  } catch {
    return false;
  }
}