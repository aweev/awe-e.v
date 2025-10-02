// lib/api-client/base.ts

import { useAuthStore } from "@/stores/auth.store";
import type { LoginResponse } from "@/types/auth.types";
import { ApiClientError, type ApiErrorPayload } from "./errors";

// Define custom options that extend the native RequestInit
export interface ApiClientOptions extends RequestInit {
    skipAuthRefresh?: boolean;
}

type FailedRequestQueue = ((token: string | null) => void)[];

let isRefreshing = false;
let failedQueue: FailedRequestQueue = [];

const processQueue = (error: Error | null, token: string | null = null) => {
    failedQueue.forEach(callback => callback(token));
    failedQueue = [];
};

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || '/api/v1';

export async function apiClient<T>(endpoint: string, options: ApiClientOptions = {}): Promise<T> {
    const { accessToken, logout, setAuth } = useAuthStore.getState();
    const { skipAuthRefresh, ...fetchOptions } = options;
    const url = `${API_BASE_URL}${endpoint}`;

    const headers = new Headers(fetchOptions.headers);
    if (accessToken && !headers.has("Authorization")) {
        headers.set("Authorization", `Bearer ${accessToken}`);
    }

    const response = await fetch(url, { ...fetchOptions, headers, credentials: 'include' as const });

    if (response.ok) {
        if (response.status === 204) return {} as T;
        return response.json() as Promise<T>;
    }

    if (response.status === 401 && !skipAuthRefresh) {
        if (!isRefreshing) {
            isRefreshing = true;
            try {
                const refreshResponse = await fetch(`${API_BASE_URL}/auth/refresh`, {
                    method: "POST",
                    credentials: 'include' as const,
                });

                if (!refreshResponse.ok) {
                    const errorPayload = await refreshResponse.json() as ApiErrorPayload;
                    throw new ApiClientError(refreshResponse.status, errorPayload);
                }

                const authData = await refreshResponse.json() as LoginResponse;

                // Call the new setAuth action
                setAuth({
                    user: authData.user!,
                    accessToken: authData.accessToken!,
                });
                processQueue(null, authData.accessToken);

                headers.set("Authorization", `Bearer ${authData.accessToken}`);
                const retryResponse = await fetch(url, { ...fetchOptions, headers });

                if (!retryResponse.ok) {
                    const errorPayload = await retryResponse.json() as ApiErrorPayload;
                    throw new ApiClientError(retryResponse.status, errorPayload);
                }
                if (retryResponse.status === 204) return {} as T;
                return retryResponse.json() as Promise<T>;

            } catch (error) {
                const clientError = error instanceof ApiClientError
                    ? error
                    : new ApiClientError(500, { error: (error as Error).message || "Token refresh failed" });

                processQueue(clientError, null);
                logout(); // Logout on refresh failure
                return Promise.reject(clientError);
            } finally {
                isRefreshing = false;
            }
        } else {
            return new Promise<T>((resolve, reject) => {
                failedQueue.push((newAccessToken: string | null) => {
                    if (newAccessToken) {
                        const newHeaders = new Headers(options.headers);
                        newHeaders.set("Authorization", `Bearer ${newAccessToken}`);
                        resolve(apiClient<T>(endpoint, { ...options, headers: newHeaders }));
                    } else {
                        reject(new ApiClientError(401, { error: 'Session refresh failed.' }));
                    }
                });
            });
        }
    }

    const errorPayload = await response.json() as ApiErrorPayload;
    return Promise.reject(new ApiClientError(response.status, errorPayload));
}

function createRequestHeaders(existingHeaders: HeadersInit | undefined): Headers {
    const headers = new Headers(existingHeaders);
    if (!headers.has('Content-Type')) {
        headers.set('Content-Type', 'application/json');
    }
    return headers;
}

// Update method signatures to use ApiClientOptions
apiClient.get = <T>(url: string, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'GET' });
apiClient.post = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'POST', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });
apiClient.put = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'PUT', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });
apiClient.delete = <T>(url: string, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'DELETE' });
apiClient.deleteWithBody = <T>(url: string, body: unknown, options?: ApiClientOptions) => apiClient<T>(url, { ...options, method: 'DELETE', body: JSON.stringify(body), headers: createRequestHeaders(options?.headers) });

export default apiClient;