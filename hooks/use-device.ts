// hooks/use-devices.ts
import { useState, useEffect, useCallback } from 'react';
import { useAuthStore } from '@/stores/auth.store';
import { toast } from 'sonner';
import { handleFormError } from '@/lib/api/error-handler.client';

export function useDevices() {
    const [devices, setDevices] = useState<any[]>([]);
    const [isLoading, setIsLoading] = useState(false);
    const { getDevices, trustDevice, revokeDevice } = useAuthStore();

    const fetchDevices = useCallback(async () => {
        setIsLoading(true);
        try {
            const deviceList = await getDevices();
            setDevices(deviceList);
        } catch (error) {
            handleFormError(error);
        } finally {
            setIsLoading(false);
        }
    }, [getDevices]);

    useEffect(() => {
        fetchDevices();
    }, [fetchDevices]);

    const handleTrustDevice = useCallback(
        async (deviceId: string) => {
            try {
                const result = await trustDevice(deviceId);
                if (result.success) {
                    toast.success('Device trusted successfully');
                    await fetchDevices();
                }
                return result.success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [trustDevice, fetchDevices]
    );

    const handleRevokeDevice = useCallback(
        async (deviceId: string) => {
            try {
                const result = await revokeDevice(deviceId);
                if (result.success) {
                    toast.success('Device revoked successfully');
                    await fetchDevices();
                }
                return result.success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [revokeDevice, fetchDevices]
    );

    return {
        devices,
        isLoading,
        trustDevice: handleTrustDevice,
        revokeDevice: handleRevokeDevice,
        refetch: fetchDevices,
    };
}