// lib/logger.ts

import pino from 'pino';

let logger: pino.Logger;

const isDev = process.env.NODE_ENV === 'development';
const usePretty = process.env.LOG_PRETTY === 'true';

if (isDev && usePretty) {
    console.log('✅ Initializing pino-pretty logger for development...');
    logger = pino({
        level: 'debug',
        transport: {
            target: 'pino-pretty',
            options: {
                colorize: true,
                translateTime: 'SYS:standard',
                ignore: 'pid,hostname',
            },
        },
    });
} else {
    logger = pino({
        level: process.env.LOG_LEVEL || 'info',
    });
}

export { logger };