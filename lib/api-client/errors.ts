// lib/api-client/errors.ts

export interface ApiErrorPayload {
    error: string;
    code?: string;
    details?: any; // For Zod validation errors
    issues?: string[]; // For password policy violations
    lockedUntil?: Date;
}

export class ApiClientError extends Error {
    public readonly status: number;
    public readonly payload: ApiErrorPayload;

    constructor(status: number, payload: ApiErrorPayload) {
        super(payload.error || 'An API error occurred');
        this.name = 'ApiClientError';
        this.status = status;
        this.payload = payload;
    }
}

/**
 * Type guard to check if an error is an instance of ApiClientError.
 * This is the correct way to check for our custom error on the client.
 */
export function isApiClientError(error: unknown): error is ApiClientError {
    return error instanceof ApiClientError;
}