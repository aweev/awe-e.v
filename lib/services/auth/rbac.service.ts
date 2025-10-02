// lib/services/auth/rbac.service.ts
import 'server-only';
import { prisma } from "@/lib/db";
import { Role } from "@prisma/client";
import { LRUCache } from 'lru-cache';
import type { PermissionString } from '@/lib/audit/actions';
import { logger } from '@/lib/logger';

const rolePermissionsCache = new LRUCache<Role, PermissionString[]>({
  max: 100,
  ttl: 1000 * 60 * 5,
});

class RBACService {
  async getPermissionsForRoles(roles: Role[]): Promise<Set<PermissionString>> {
    const allPermissions = new Set<PermissionString>();

    if (!roles || roles.length === 0) {
      return allPermissions;
    }

    for (const role of roles) {
      if (rolePermissionsCache.has(role)) {
        rolePermissionsCache.get(role)!.forEach(p => allPermissions.add(p));
        continue;
      }

      const rolePerms = await prisma.rolePermission.findMany({
        where: { role },
        include: { permission: true },
      });

      const permissions = rolePerms.map(
        rp => `${rp.permission.resource}:${rp.permission.action}` as PermissionString
      );

      rolePermissionsCache.set(role, permissions);
      permissions.forEach(p => allPermissions.add(p));
    }

    return allPermissions;
  }


  async startImpersonation(adminUserId: string, targetUserId: string): Promise<void> {
    const adminUser = await prisma.user.findUnique({ where: { id: adminUserId } });
    if (!adminUser || !adminUser.roles.includes(Role.SUPER_ADMIN)) {
      throw new Error("Forbidden: Only Super Admins can impersonate users.");
    }

    await prisma.user.update({
      where: { id: adminUserId },
      data: { impersonatingUserId: targetUserId },
    });
  }

  async stopImpersonation(adminUserId: string): Promise<void> {
    await prisma.user.update({
      where: { id: adminUserId },
      data: { impersonatingUserId: null },
    });
  }

  async invalidateCacheForRole(role: Role): Promise<void> {
    rolePermissionsCache.delete(role);
    logger.info({ role }, `[RBAC Cache] Invalidated cache for role`);
  }
}

export const rbacService = new RBACService();