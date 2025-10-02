// lib/lucia.ts

import { Lucia } from "lucia";
import { PrismaAdapter } from "@lucia-auth/adapter-prisma";
import { prisma } from "@/lib/db";

const adapter = new PrismaAdapter(prisma.userSession, prisma.user);

export const auth = new Lucia(adapter, {
    sessionCookie: {
        attributes: {
            secure: process.env.NODE_ENV === "production"
        }
    },
    getUserAttributes: (user) => {
        return {
            id: user.id,
            email: user.email
        };
    }
});

export type Auth = typeof auth;
