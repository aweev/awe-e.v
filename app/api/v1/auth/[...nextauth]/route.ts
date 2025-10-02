// app/api/auth/[...auth]/route.ts
import { NextRequest } from "next/server";
import { auth } from "@/lib/lucia";

export async function GET(req: NextRequest) {
    const authRequest = auth.handleRequest({
        request: req,
        cookies: {
            get: (name) => req.cookies.get(name)?.value ?? null,
            set: () => { }, // Next.js App Router requires `Response.cookies.set()` instead
            delete: () => { }
        }
    });

    const session = await authRequest.validate();
    return Response.json(session);
}

export async function POST(req: NextRequest) {
    const authRequest = auth.handleRequest({
        request: req,
        cookies: {
            get: (name) => req.cookies.get(name)?.value ?? null,
            set: () => { },
            delete: () => { }
        }
    });

    const session = await authRequest.validate();
    return Response.json(session);
}
