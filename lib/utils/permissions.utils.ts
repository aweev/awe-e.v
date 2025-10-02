// lib/auth/permissions.utils.ts
import { PERMISSIONS } from '@/lib/audit/actions';
import type { PermissionString } from '@/lib/audit/actions';

export function hasPermission(
    userPermissions: Set<PermissionString>,
    requiredPermission: PermissionString
): boolean {
    if (userPermissions.has(PERMISSIONS.ALL_MANAGE)) {
        return true;
    }

    if (userPermissions.has(requiredPermission)) {
        return true;
    }

    const resource = requiredPermission.split(':')[0];
    const managePermission = `${resource}:manage` as PermissionString;
    if (userPermissions.has(managePermission)) {
        return true;
    }

    return false;
}