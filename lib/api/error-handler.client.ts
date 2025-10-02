// lib/api/error-handler.client.ts
import { toast } from 'sonner';
import { ApiClientError, isApiClientError } from '@/lib/api-client/errors';

export function getErrorMessage(error: unknown): string {
    if (isApiClientError(error)) {
        return error.payload.error || 'An error occurred';
    }
    if (error instanceof Error) {
        return error.message;
    }
    return 'An unexpected error occurred';
}

export function getErrorCode(error: unknown): string | undefined {
    if (isApiClientError(error)) {
        return error.payload.code;
    }
    return undefined;
}

export function showErrorToast(error: unknown, fallbackMessage?: string): void {
    const message = getErrorMessage(error);
    toast.error(message || fallbackMessage || 'An error occurred');
}


export function isErrorType(error: unknown, code: string): boolean {
    return getErrorCode(error) === code;
}

export function showValidationErrors(error: unknown): void {
    if (isApiClientError(error) && error.payload.code === 'VALIDATION_ERROR' && error.payload.details?.fieldErrors) {
        const fieldErrors = error.payload.details.fieldErrors as Record<string, string[]>;
        Object.entries(fieldErrors).forEach(([field, errors]) => {
            errors.forEach((err) => {
                // Capitalize field name for better readability
                const formattedField = field.charAt(0).toUpperCase() + field.slice(1);
                toast.error(`${formattedField}: ${err}`);
            });
        });
    } else {
        showErrorToast(error, 'Validation failed. Please check your input.');
    }
}

export function showPasswordPolicyErrors(error: unknown): void {
    if (isApiClientError(error) && error.payload.code === 'PASSWORD_POLICY_VIOLATION' && error.payload.issues) {
        error.payload.issues.forEach((issue: string) => {
            toast.error(issue, { duration: 5000 });
        });
    } else {
        showErrorToast(error, 'Password does not meet the security requirements.');
    }
}

export function handleFormError(error: unknown): void {
    if (isApiClientError(error)) {
        switch (error.payload.code) {
            case 'VALIDATION_ERROR':
                showValidationErrors(error);
                break;
            case 'PASSWORD_POLICY_VIOLATION':
                showPasswordPolicyErrors(error);
                break;
            default:
                showErrorToast(error);
        }
    } else {
        showErrorToast(error, 'An unexpected error occurred.');
    }
}

export function isNetworkError(error: unknown): boolean {
    return !(error instanceof ApiClientError) && error instanceof TypeError;
}

export function isAuthenticationError(error: unknown): boolean {
    return isApiClientError(error) && error.status === 401;
}

export function isAuthorizationError(error: unknown): boolean {
    return isApiClientError(error) && error.status === 403;
}

export function isValidationError(error: unknown): boolean {
    return isErrorType(error, 'VALIDATION_ERROR');
}