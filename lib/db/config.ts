// lib/db/config.ts
import { PrismaClient } from '@prisma/client';

const globalForPrisma = globalThis as unknown as {
    prisma: PrismaClient | undefined;
};

function createPrismaClient() {
    const isProduction = process.env.NODE_ENV === 'production';

    return new PrismaClient({
        log: isProduction ? ['error'] : ['query', 'info', 'warn', 'error'],
        errorFormat: 'pretty',
    });
}

export const prisma = globalForPrisma.prisma ?? createPrismaClient();

if (process.env.NODE_ENV !== 'production') {
    globalForPrisma.prisma = prisma;
}