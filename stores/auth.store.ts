// stores/auth.store.ts
import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import { AuthUser, LoginResponse } from '@/types/auth.types';
import { apiClient } from '@/lib/api-client/base';
import { isApiError } from '@/lib/api/error-handler';

interface AuthState {
    // State
    user: AuthUser | null;
    accessToken: string | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    deviceVerificationRequired: boolean;
    deviceId: string | null;
    mfaRequired: boolean;
    mfaToken: string | null;
    loginError: string | null;
    mfaError: string | null;

    // Actions
    setAuth: (data: { user: AuthUser; accessToken: string }) => void;
    login: (email: string, password: string, rememberMe?: boolean) => Promise<{ success: boolean; error?: string }>;
    loginWithMfa: (code: string, mfaToken: string) => Promise<{ success: boolean; error?: string }>;
    verifyDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
    register: (email: string, password: string, confirmPassword: string) => Promise<{ success: boolean; error?: string; issues?: string[]; requiresVerification?: boolean }>;
    logout: () => Promise<void>;
    refreshAccessToken: () => Promise<void>;
    changePassword: (currentPassword: string, newPassword: string, confirmPassword: string) => Promise<{ success: boolean; error?: string; issues?: string[] }>;
    fetchUser: () => Promise<void>;
    clearAuth: () => void;

    // OAuth
    loginWithGoogle: (code: string, redirectUri: string) => Promise<{ success: boolean; error?: string }>;
    loginWithFacebook: (code: string, redirectUri: string) => Promise<{ success: boolean; error?: string }>;

    // Device Management
    getDevices: () => Promise<any[]>;
    trustDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
    revokeDevice: (deviceId: string) => Promise<{ success: boolean; error?: string }>;
}

export const useAuthStore = create<AuthState>()(
    persist(
        (set, get) => ({
            // Initial state
            user: null,
            accessToken: null,
            isAuthenticated: false,
            isLoading: false,
            deviceVerificationRequired: false,
            deviceId: null,
            mfaRequired: false,
            mfaToken: null,
            loginError: null,
            mfaError: null,

            setAuth: (data: { user: AuthUser; accessToken: string }) => {
                set({
                    user: data.user,
                    accessToken: data.accessToken,
                    isAuthenticated: true,
                    isLoading: false,
                    // Reset flow states
                    deviceVerificationRequired: false,
                    deviceId: null,
                    mfaRequired: false,
                    mfaToken: null,
                    loginError: null,
                });
            },

            // Login with email and password
            login: async (email: string, password: string, rememberMe = false) => {
                set({ isLoading: true, loginError: null });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/login', {
                        email,
                        password,
                        rememberMe
                    });

                    // Handle different response types
                    if (response.mfaRequired) {
                        set({
                            mfaRequired: true,
                            mfaToken: response.mfaToken,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    // Successful login
                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null,
                        mfaRequired: false,
                        mfaToken: null,
                        loginError: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Login failed';

                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        switch (errorData.code) {
                            case 'ACCOUNT_LOCKED':
                                errorMessage = `Account locked. Try again after ${new Date(errorData.lockedUntil!).toLocaleString()}`;
                                break;
                            case 'INVALID_CREDENTIALS':
                                errorMessage = 'Invalid email or password';
                                break;
                            case 'VALIDATION_ERROR':
                                errorMessage = 'Please check your email and password';
                                break;
                            default:
                                errorMessage = errorData.error || 'An unknown login error occurred';
                        }
                    } else {
                        errorMessage = 'Network error occurred. Please try again';
                    }

                    set({ isLoading: false, loginError: errorMessage });
                    return { success: false, error: errorMessage };
                }
            },

            // Login with MFA
            loginWithMfa: async (code: string, mfaToken: string) => {
                set({ isLoading: true, mfaError: null });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/mfa/verify', {
                        code,
                        mfaToken
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        mfaRequired: false,
                        mfaToken: null,
                        mfaError: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'MFA verification failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false, mfaError: errorMessage });
                    return { success: false, error: errorMessage };
                }
            },

            // Verify device
            verifyDevice: async (deviceId: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/verify-device', {
                        deviceId
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Device verification failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // Register new user
            register: async (email: string, password: string, confirmPassword: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<{ requiresVerification: boolean }>('/auth/register', {
                        email,
                        password,
                        confirmPassword
                    });

                    set({ isLoading: false });

                    return {
                        success: true,
                        requiresVerification: response.requiresVerification
                    };
                } catch (error: unknown) {
                    set({ isLoading: false });

                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        if (errorData.code === 'PASSWORD_POLICY_VIOLATION') {
                            return {
                                success: false,
                                error: errorData.error,
                                issues: errorData.issues,
                            };
                        }

                        return {
                            success: false,
                            error: errorData.error || 'Registration failed',
                        };
                    }

                    return {
                        success: false,
                        error: 'Network error occurred during registration',
                    };
                }
            },

            // Logout
            logout: async () => {
                try {
                    await apiClient.post('/auth/logout', undefined, { skipAuthRefresh: true });
                } catch (error) {
                    console.error('Logout error:', error);
                } finally {
                    get().clearAuth();
                }
            },

            // Refresh access token
            refreshAccessToken: async () => {
                try {
                    const response = await apiClient.post<LoginResponse>('/auth/refresh', undefined, {
                        skipAuthRefresh: true
                    });

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true
                    });
                } catch (error) {
                    get().clearAuth();
                    throw error;
                }
            },

            // Change password
            changePassword: async (currentPassword: string, newPassword: string, confirmPassword: string) => {
                try {
                    await apiClient.post('/auth/change-password', {
                        currentPassword,
                        newPassword,
                        confirmPassword
                    });

                    return { success: true };
                } catch (error: unknown) {
                    if (isApiError(error) && error.response?.data) {
                        const errorData = error.response.data;

                        if (errorData.code === 'PASSWORD_POLICY_VIOLATION') {
                            return {
                                success: false,
                                error: errorData.error,
                                issues: errorData.issues
                            };
                        }

                        return {
                            success: false,
                            error: errorData.error || 'Password change failed'
                        };
                    }

                    return {
                        success: false,
                        error: 'Network error occurred'
                    };
                }
            },

            // Fetch current user
            fetchUser: async () => {
                try {
                    const response = await apiClient.get<{ user: AuthUser }>('/auth/me');

                    set({
                        user: response.user,
                        isAuthenticated: true
                    });
                } catch (error) {
                    get().clearAuth();
                }
            },

            // Clear auth state
            clearAuth: () => {
                set({
                    user: null,
                    accessToken: null,
                    isAuthenticated: false,
                    isLoading: false,
                    deviceVerificationRequired: false,
                    deviceId: null,
                    mfaRequired: false,
                    mfaToken: null,
                    loginError: null,
                    mfaError: null
                });
            },

            // OAuth login with Google
            loginWithGoogle: async (code: string, redirectUri: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/oauth/google', {
                        code,
                        redirectUri
                    });

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Google login failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // OAuth login with Facebook
            loginWithFacebook: async (code: string, redirectUri: string) => {
                set({ isLoading: true });

                try {
                    const response = await apiClient.post<LoginResponse>('/auth/oauth/facebook', {
                        code,
                        redirectUri
                    });

                    if (response.deviceVerificationRequired) {
                        set({
                            deviceVerificationRequired: true,
                            deviceId: response.deviceId,
                            isLoading: false
                        });
                        return { success: true };
                    }

                    set({
                        user: response.user!,
                        accessToken: response.accessToken!,
                        isAuthenticated: true,
                        isLoading: false,
                        deviceVerificationRequired: false,
                        deviceId: null
                    });

                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Facebook login failed';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    set({ isLoading: false });
                    return { success: false, error: errorMessage };
                }
            },

            // Get user devices
            getDevices: async () => {
                try {
                    const response = await apiClient.get<{ devices: any[] }>('/auth/devices');
                    return response.devices;
                } catch (error) {
                    console.error('Failed to fetch devices:', error);
                    return [];
                }
            },

            // Trust a device
            trustDevice: async (deviceId: string) => {
                try {
                    await apiClient.post('/auth/devices', { deviceId });
                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Failed to trust device';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    return { success: false, error: errorMessage };
                }
            },

            // Revoke a device
            revokeDevice: async (deviceId: string) => {
                try {
                    await apiClient.deleteWithBody('/auth/devices', { deviceId });
                    return { success: true };
                } catch (error: unknown) {
                    let errorMessage = 'Failed to revoke device';

                    if (isApiError(error) && error.response?.data) {
                        errorMessage = error.response.data.error || errorMessage;
                    }

                    return { success: false, error: errorMessage };
                }
            }
        }),
        {
            name: 'auth-storage',
            storage: createJSONStorage(() => localStorage),
            partialize: (state) => ({
                user: state.user,
                accessToken: state.accessToken,
                isAuthenticated: state.isAuthenticated
            })
        }
    )
);