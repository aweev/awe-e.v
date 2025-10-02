// lib/api-client/user.client.ts
import {
    PaginationParams,
    PaginationResult,
    UpdatePreferencesData,
    UpdateProfileData,
    UserDeviceDto,
    UserExportData,
    UserSearchFilters,
    UserStats,
    BulkUserOperation,
    ProfileCompletionStatus,
    SkillData,
} from '@/types/user.types';
import { User, UserProfile, UserPreferences, UserSkill, Role } from '@prisma/client';
import { apiClient } from './base';

// A more complete User DTO for the client
export interface UserDto extends Omit<User, 'hashedPassword' | 'mfaSecret'> {
    profile: UserProfile | null;
    preferences: UserPreferences | null;
}

export const userClient = {
    // Core User
    getById: (userId: string) => apiClient.get<{ user: UserDto }>(`/users/${userId}`),
    search: (params: UserSearchFilters & PaginationParams & { q?: string }) => {
        const query = new URLSearchParams(params as any).toString();
        return apiClient.get<PaginationResult<UserDto>>(`/users/search?${query}`);
    },

    // Profile
    updateProfile: (userId: string, data: UpdateProfileData) =>
        apiClient.patch<{ profile: UserProfile }>(`/users/${userId}/profile`, data),
    getProfileCompletion: (userId: string) =>
        apiClient.get<{ completion: ProfileCompletionStatus }>(`/users/${userId}/profile`),

    // Preferences
    getPreferences: (userId: string) =>
        apiClient.get<{ preferences: UserPreferences }>(`/users/${userId}/preferences`),
    updatePreferences: (userId: string, data: UpdatePreferencesData) =>
        apiClient.patch<{ preferences: UserPreferences }>(`/users/${userId}/preferences`, data),

    // Avatar
    updateAvatar: (userId: string, avatarUrl: string) =>
        apiClient.post<{ user: UserDto }>(`/users/${userId}/avatar`, { avatarUrl }),
    deleteAvatar: (userId: string) => apiClient.delete(`/users/${userId}/avatar`),

    // Skills
    getSkills: (userId: string) => apiClient.get<{ skills: UserSkill[] }>(`/users/${userId}/skills`),
    addOrUpdateSkill: (userId: string, data: SkillData) =>
        apiClient.post<{ skill: UserSkill }>(`/users/${userId}/skills`, data),
    removeSkill: (userId: string, skillId: string) =>
        apiClient.delete(`/users/${userId}/skills/${skillId}`),
    bulkUpdateSkills: (userId: string, skills: SkillData[]) =>
        apiClient.put<{ skills: UserSkill[] }>(`/users/${userId}/skills`, { skills }),

    // Stats & Activity
    getStats: (userId: string, days: number = 30) =>
        apiClient.get<{ stats: UserStats; activity: any }>(`/users/${userId}/stats?days=${days}`),

    // Devices
    getDevices: (userId: string) => apiClient.get<{ devices: UserDeviceDto[] }>(`/users/${userId}/devices`),
    revokeAllDevices: (userId: string, currentDeviceId: string) =>
        apiClient.delete<{ count: number }>(`/users/${userId}/devices`, { body: { currentDeviceId } }),

    // GDPR & Account Management
    exportData: (userId: string) => apiClient.get<UserExportData>(`/users/${userId}/export`),
    deleteAccount: (userId: string, reason?: string) =>
        apiClient.delete(`/users/${userId}`, { body: { reason } }),

    // Roles (Admin)
    bulkAssignRoles: (data: BulkUserOperation) =>
        apiClient.post('/users/roles/assign', data),
};