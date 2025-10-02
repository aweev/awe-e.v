// lib/db/index.ts
import { PrismaClient } from '@prisma/client';

// PrismaClient is attached to the `global` object in development to prevent
// exhausting your database connection limit.
// See https://pris.ly/d/help/next-js-best-practices

const globalForPrisma = globalThis as unknown as { prisma: PrismaClient | undefined };

const isProduction = process.env.NODE_ENV === 'production';

export const prisma =
  globalForPrisma.prisma ??
  new PrismaClient({
    log: isProduction ? ['error'] : ['query', 'info', 'warn', 'error'],
  });

if (!isProduction) globalForPrisma.prisma = prisma;

// // lib/db.ts
// import { PrismaClient } from '@prisma/client';

// type TGlobal = typeof globalThis & {
//   prisma?: PrismaClient;
// };

// const prismaClientSingleton = () => {
//   return new PrismaClient({
//     log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
//   });
// };

// export const prisma = (globalThis as TGlobal).prisma ?? prismaClientSingleton();

// if (process.env.NODE_ENV !== 'production') {
//   (globalThis as TGlobal).prisma = prisma;
// }


// import { PrismaClient } from '@prisma/client';

// // This prevents creating new connections on every hot-reload in development
// declare global {
//   // allow global `var` declarations
//   // eslint-disable-next-line no-var
//   var prisma: PrismaClient | undefined;
// }

// export const prisma =
//   global.prisma ||
//   new PrismaClient({
//     log: process.env.NODE_ENV === 'development' ? ['query', 'error', 'warn'] : ['error'],
//   });

// if (process.env.NODE_ENV !== 'production') {
//   global.prisma = prisma;
// }