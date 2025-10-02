// types/lucia.d.ts
import type { auth } from "@/lib/lucia";

declare module "lucia" {
    interface Register {
        Lucia: typeof auth;
        DatabaseUserAttributes: {
            id: string;
            email: string;
        };
    }
}
