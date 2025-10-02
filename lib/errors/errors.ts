// lib/errors/errors.ts

/**
 * Base class for all application-specific errors.
 * Allows for consistent error handling and structured error responses.
 */
export class AppError extends Error {
    public readonly code: string;
    public readonly statusCode: number;
    public readonly details?: unknown;

    constructor(message: string, code: string, statusCode: number, details?: unknown) {
        super(message);
        this.name = this.constructor.name;
        this.code = code;
        this.statusCode = statusCode;
        this.details = details;
        Error.captureStackTrace(this, this.constructor);
    }
}

/**
 * Thrown when a resource is not found.
 * HTTP Status: 404
 */
export class NotFoundError extends AppError {
    constructor(resource: string = 'Resource') {
        super(`${resource} not found`, `${resource.toUpperCase()}_NOT_FOUND`, 404);
    }
}

/**
 * Thrown when input data fails validation.
 * HTTP Status: 400
 */
export class ValidationError extends AppError {
    constructor(message: string, details?: unknown) {
        super(message, 'VALIDATION_ERROR', 400, details);
    }
}

/**
 * Thrown when a user is not authorized to perform an action.
 * HTTP Status: 403
 */
export class ForbiddenError extends AppError {
    constructor(message: string = 'You do not have permission to perform this action.') {
        super(message, 'FORBIDDEN', 403);
    }
}

/**
 * Thrown for general server-side errors.
 * HTTP Status: 500
 */
export class InternalServerError extends AppError {
    constructor(message: string = 'An unexpected internal error occurred.') {
        super(message, 'INTERNAL_SERVER_ERROR', 500);
    }
}