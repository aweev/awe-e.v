// hooks/use-user.ts
import { useUserStore } from '@/stores/user.store';
import { useAuthStore } from '@/stores/auth.store';
import { useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { UpdateProfileData, UpdatePreferencesData } from '@/types/user.types';
import { handleFormError } from '@/lib/api/error-handler.client';

export function useUser() {
    const { user: authUser } = useAuthStore();
    const {
        profile,
        preferences,
        skills,
        isLoading,
        error,
        fetchProfile,
        updateProfile,
        updatePreferences,
        fetchSkills,
        addSkill,
        removeSkill,
    } = useUserStore();

    // Auto-fetch on mount
    useEffect(() => {
        if (authUser?.id && !profile) {
            fetchProfile();
        }
    }, [authUser?.id, profile, fetchProfile]);

    const handleUpdateProfile = useCallback(
        async (data: UpdateProfileData) => {
            try {
                const success = await updateProfile(data);
                if (success) {
                    toast.success('Profile updated successfully');
                }
                return success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [updateProfile]
    );

    const handleUpdatePreferences = useCallback(
        async (data: UpdatePreferencesData) => {
            try {
                const success = await updatePreferences(data);
                if (success) {
                    toast.success('Preferences updated successfully');
                }
                return success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [updatePreferences]
    );

    const handleAddSkill = useCallback(
        async (skillId: string, level: any) => {
            try {
                const success = await addSkill(skillId, level);
                if (success) {
                    toast.success('Skill added successfully');
                }
                return success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [addSkill]
    );

    const handleRemoveSkill = useCallback(
        async (skillId: string) => {
            try {
                const success = await removeSkill(skillId);
                if (success) {
                    toast.success('Skill removed successfully');
                }
                return success;
            } catch (error) {
                handleFormError(error);
                return false;
            }
        },
        [removeSkill]
    );

    return {
        profile,
        preferences,
        skills,
        isLoading,
        error,
        updateProfile: handleUpdateProfile,
        updatePreferences: handleUpdatePreferences,
        fetchSkills,
        addSkill: handleAddSkill,
        removeSkill: handleRemoveSkill,
        refetch: fetchProfile,
    };
}
