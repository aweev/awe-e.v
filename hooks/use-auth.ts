// hooks/use-auth.ts
import { useAuthStore } from '@/stores/auth.store';
import { useRouter } from 'next/navigation';
import { useCallback } from 'react';
import { toast } from 'sonner';
import { handleFormError } from '@/lib/api/error-handler.client';

export function useAuth() {
    const router = useRouter();
    const {
        user,
        isAuthenticated,
        isLoading,
        login,
        logout,
        register,
        loginWithMfa,
        verifyDevice,
        changePassword,
        deviceVerificationRequired,
        deviceId,
        mfaRequired,
        mfaToken,
        loginError,
        mfaError,
    } = useAuthStore();

    const handleLogin = useCallback(
        async (email: string, password: string, rememberMe = false) => {
            try {
                const result = await login(email, password, rememberMe);

                if (result.success) {
                    // Check if MFA or device verification is required
                    if (mfaRequired) {
                        toast.info('MFA verification required');
                        router.push('/auth/mfa');
                        return { requiresMfa: true };
                    }

                    if (deviceVerificationRequired) {
                        toast.info('New device detected. Please verify.');
                        router.push('/auth/verify-device');
                        return { requiresDeviceVerification: true };
                    }

                    toast.success('Login successful');
                    router.push('/dashboard');
                    return { success: true };
                }

                return result;
            } catch (error) {
                handleFormError(error);
                return { success: false, error: 'Login failed' };
            }
        },
        [login, router, mfaRequired, deviceVerificationRequired]
    );

    const handleLogout = useCallback(async () => {
        try {
            await logout();
            toast.success('Logged out successfully');
            router.push('/login');
        } catch (error) {
            console.error('Logout error:', error);
        }
    }, [logout, router]);

    const handleRegister = useCallback(
        async (email: string, password: string, confirmPassword: string) => {
            try {
                const result = await register(email, password, confirmPassword);

                if (result.success) {
                    if (result.requiresVerification) {
                        toast.success('Registration successful! Please check your email.');
                        router.push('/auth/verify-email-sent');
                    }
                    return result;
                }

                if (result.issues) {
                    result.issues.forEach((issue) => toast.error(issue));
                }

                return result;
            } catch (error) {
                handleFormError(error);
                return { success: false, error: 'Registration failed' };
            }
        },
        [register, router]
    );

    const handleMfaVerification = useCallback(
        async (code: string) => {
            if (!mfaToken) {
                toast.error('MFA session expired. Please login again.');
                router.push('/login');
                return { success: false };
            }

            try {
                const result = await loginWithMfa(code, mfaToken);

                if (result.success) {
                    toast.success('MFA verification successful');
                    router.push('/dashboard');
                }

                return result;
            } catch (error) {
                handleFormError(error);
                return { success: false };
            }
        },
        [loginWithMfa, mfaToken, router]
    );

    const handleDeviceVerification = useCallback(
        async () => {
            if (!deviceId) {
                toast.error('Device verification session expired. Please login again.');
                router.push('/login');
                return { success: false };
            }

            try {
                const result = await verifyDevice(deviceId);

                if (result.success) {
                    toast.success('Device verified successfully');
                    router.push('/dashboard');
                }

                return result;
            } catch (error) {
                handleFormError(error);
                return { success: false };
            }
        },
        [verifyDevice, deviceId, router]
    );

    const handleChangePassword = useCallback(
        async (currentPassword: string, newPassword: string, confirmPassword: string) => {
            try {
                const result = await changePassword(currentPassword, newPassword, confirmPassword);

                if (result.success) {
                    toast.success('Password changed successfully. Please login again.');
                    await logout();
                    router.push('/login');
                }

                return result;
            } catch (error) {
                handleFormError(error);
                return { success: false };
            }
        },
        [changePassword, logout, router]
    );

    return {
        user,
        isAuthenticated,
        isLoading,
        login: handleLogin,
        logout: handleLogout,
        register: handleRegister,
        verifyMfa: handleMfaVerification,
        verifyDevice: handleDeviceVerification,
        changePassword: handleChangePassword,
        mfaRequired,
        deviceVerificationRequired,
        loginError,
        mfaError,
    };
}

