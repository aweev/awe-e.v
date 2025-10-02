// lib/services/auth/device-management.service.ts
import { prisma } from '@/lib/db';
import { add } from 'date-fns';
import { auditService } from '@/lib/audit.service';
import { AUDIT_ACTIONS } from '@/lib/audit/actions';

export interface DeviceInfo {
    userAgent: string;
    ip: string;
    platform?: string;
    browser?: string;
    os?: string;
    device?: string;
    fingerprint?: string;
}

export interface TrustedDeviceConfig {
    maxDevices: number;
    trustDurationDays: number;
    requireVerificationForNewDevices: boolean;
}

const DEFAULT_CONFIG: TrustedDeviceConfig = {
    maxDevices: 5,
    trustDurationDays: 30,
    requireVerificationForNewDevices: true,
};

export class NewDeviceError extends Error {
    constructor(
        public deviceId: string,
        message = 'New device detected. Please verify this device.'
    ) {
        super(message);
        this.name = 'NewDeviceError';
    }
}

export const deviceManagementService = {
    async getConfig(): Promise<TrustedDeviceConfig> {
        // In a real implementation, you might fetch this from a settings table
        return DEFAULT_CONFIG;
    },

    parseDeviceInfo(userAgent: string, ip: string): DeviceInfo {
        // Simple parsing of user agent - in production, you might use a library like ua-parser-js
        const browserMatch = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)\/?([\d.]+)?/);
        const osMatch = userAgent.match(/\(([^)]+)\)/);
        const platformMatch = userAgent.match(/(Windows|Mac|Linux|Android|iOS)/);

        return {
            userAgent,
            ip,
            platform: platformMatch ? platformMatch[1] : 'Unknown',
            browser: browserMatch ? browserMatch[1] : 'Unknown',
            os: osMatch ? osMatch[1] : 'Unknown',
            device: 'Unknown' // Would need more sophisticated parsing to detect device type
        };
    },

    async getDeviceFingerprint(deviceInfo: DeviceInfo): Promise<string> {
        // Create a simple fingerprint from device info
        // In production, you might use more sophisticated fingerprinting
        const fingerprintString = `${deviceInfo.platform}-${deviceInfo.browser}-${deviceInfo.os}`;
        return require('crypto').createHash('sha256').update(fingerprintString).digest('hex');
    },

    async recordDevice(
        userId: string,
        deviceInfo: DeviceInfo,
        isTrusted: boolean = false
    ): Promise<{ isNewDevice: boolean; deviceId: string; requiresVerification?: boolean }> {
        const fingerprint = await this.getDeviceFingerprint(deviceInfo);
        const config = await this.getConfig();

        // Check if this device already exists for the user
        const existingDevice = await prisma.trustedDevice.findFirst({
            where: {
                userId,
                fingerprint
            }
        });

        if (existingDevice) {
            // Update last used timestamp
            await prisma.trustedDevice.update({
                where: { id: existingDevice.id },
                data: {
                    lastUsedAt: new Date(),
                    lastIp: deviceInfo.ip
                }
            });

            return {
                isNewDevice: false,
                deviceId: existingDevice.id
            };
        }

        // Check if user has reached max devices
        const deviceCount = await prisma.trustedDevice.count({
            where: { userId, isTrusted: true }
        });

        if (deviceCount >= config.maxDevices) {
            // Remove oldest device
            const oldestDevice = await prisma.trustedDevice.findFirst({
                where: { userId, isTrusted: true },
                orderBy: { lastUsedAt: 'asc' }
            });

            if (oldestDevice) {
                await prisma.trustedDevice.update({
                    where: { id: oldestDevice.id },
                    data: { isTrusted: false }
                });
            }
        }

        // Create new device record
        const newDevice = await prisma.trustedDevice.create({
            data: {
                userId,
                fingerprint,
                platform: deviceInfo.platform,
                browser: deviceInfo.browser,
                os: deviceInfo.os,
                lastIp: deviceInfo.ip,
                isTrusted,
                trustedAt: isTrusted ? new Date() : null,
                expiresAt: isTrusted ? add(new Date(), { days: config.trustDurationDays }) : null
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.NEW_DEVICE_DETECTED,
            actorId: userId,
            metadata: {
                deviceId: newDevice.id,
                platform: deviceInfo.platform,
                browser: deviceInfo.browser,
                ip: deviceInfo.ip
            }
        });

        return {
            isNewDevice: true,
            deviceId: newDevice.id,
            requiresVerification: config.requireVerificationForNewDevices && !isTrusted
        };
    },

    async trustDevice(userId: string, deviceId: string): Promise<void> {
        const config = await this.getConfig();

        await prisma.trustedDevice.update({
            where: {
                id: deviceId,
                userId // Ensure user can only trust their own devices
            },
            data: {
                isTrusted: true,
                trustedAt: new Date(),
                expiresAt: add(new Date(), { days: config.trustDurationDays })
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.DEVICE_TRUSTED,
            actorId: userId,
            metadata: { deviceId }
        });
    },

    async revokeDevice(userId: string, deviceId: string): Promise<void> {
        await prisma.trustedDevice.updateMany({
            where: {
                id: deviceId,
                userId // Ensure user can only revoke their own devices
            },
            data: {
                isTrusted: false,
                revokedAt: new Date()
            }
        });

        await auditService.log({
            action: AUDIT_ACTIONS.DEVICE_REVOKED,
            actorId: userId,
            metadata: { deviceId }
        });
    },

    async isTrustedDevice(userId: string, deviceInfo: DeviceInfo): Promise<{ isTrusted: boolean; deviceId?: string }> {
        const fingerprint = await this.getDeviceFingerprint(deviceInfo);

        const device = await prisma.trustedDevice.findFirst({
            where: {
                userId,
                fingerprint,
                isTrusted: true,
                OR: [
                    { expiresAt: null },
                    { expiresAt: { gt: new Date() } }
                ]
            }
        });

        return {
            isTrusted: !!device,
            deviceId: device?.id
        };
    },

    async getUserDevices(userId: string): Promise<any[]> {
        return prisma.trustedDevice.findMany({
            where: { userId },
            orderBy: { lastUsedAt: 'desc' }
        });
    }
};