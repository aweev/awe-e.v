// stores/user.store.ts
import { create } from 'zustand';
import { UserProfile, UserPreferences, UserSkill } from '@prisma/client';
import { userClient } from '@/lib/api-client/user.client';
import { useAuthStore } from './auth.store';
import { UpdateProfileData, UpdatePreferencesData } from '@/types/user.types';
import { showErrorToast } from '@/lib/api/error-handler.client';

interface UserState {
    profile: UserProfile | null;
    preferences: UserPreferences | null;
    skills: UserSkill[];
    isLoading: boolean;
    error: string | null;

    fetchProfile: () => Promise<void>;
    updateProfile: (data: UpdateProfileData) => Promise<boolean>;
    updatePreferences: (data: UpdatePreferencesData) => Promise<boolean>;
    fetchSkills: () => Promise<void>;
    addSkill: (skillId: string, level: any) => Promise<boolean>;
    removeSkill: (skillId: string) => Promise<boolean>;
    clearUserData: () => void;
}

export const useUserStore = create<UserState>((set, get) => ({
    profile: null,
    preferences: null,
    skills: [],
    isLoading: false,
    error: null,

    fetchProfile: async () => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return;

        set({ isLoading: true });
        try {
            const [{ user }, { preferences }] = await Promise.all([
                userClient.getById(userId),
                userClient.getPreferences(userId),
            ]);
            set({ profile: user.profile, preferences, isLoading: false, error: null });
        } catch (error) {
            const message = 'Failed to fetch profile';
            showErrorToast(error, message);
            set({ isLoading: false, error: message });
        }
    },

    updateProfile: async (data: UpdateProfileData) => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return false;

        set({ isLoading: true });
        try {
            const { profile } = await userClient.updateProfile(userId, data);
            set(state => ({
                profile: { ...state.profile, ...profile } as UserProfile,
                isLoading: false,
                error: null,
            }));
            return true;
        } catch (error) {
            const message = 'Failed to update profile';
            showErrorToast(error, message);
            set({ isLoading: false, error: message });
            return false;
        }
    },

    updatePreferences: async (data: UpdatePreferencesData) => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return false;

        set({ isLoading: true });
        try {
            const { preferences } = await userClient.updatePreferences(userId, data);
            set(state => ({
                preferences: { ...state.preferences, ...preferences } as UserPreferences,
                isLoading: false,
                error: null,
            }));
            return true;
        } catch (error) {
            const message = 'Failed to update preferences';
            showErrorToast(error, message);
            set({ isLoading: false, error: message });
            return false;
        }
    },

    fetchSkills: async () => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return;

        set({ isLoading: true });
        try {
            const { skills } = await userClient.getSkills(userId);
            set({ skills, isLoading: false, error: null });
        } catch (error) {
            const message = 'Failed to fetch skills';
            showErrorToast(error, message);
            set({ isLoading: false, error: message });
        }
    },

    addSkill: async (skillId, level) => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return false;

        try {
            const { skill } = await userClient.addOrUpdateSkill(userId, { skillId, level });
            set(state => {
                const existingIndex = state.skills.findIndex(s => s.skillId === skill.skillId);
                const newSkills = [...state.skills];
                if (existingIndex > -1) {
                    newSkills[existingIndex] = skill;
                } else {
                    newSkills.push(skill);
                }
                return { skills: newSkills };
            });
            return true;
        } catch (error) {
            showErrorToast(error, 'Failed to add skill');
            return false;
        }
    },

    removeSkill: async (skillId: string) => {
        const userId = useAuthStore.getState().user?.id;
        if (!userId) return false;

        try {
            await userClient.removeSkill(userId, skillId);
            set(state => ({
                skills: state.skills.filter(s => s.skillId !== skillId),
            }));
            return true;
        } catch (error) {
            showErrorToast(error, 'Failed to remove skill');
            return false;
        }
    },

    clearUserData: () => {
        set({ profile: null, preferences: null, skills: [], isLoading: false, error: null });
    },
}));

// Subscribe to auth store to clear user data on logout
useAuthStore.subscribe(
    (state, prevState) => {
        if (prevState.isAuthenticated && !state.isAuthenticated) {
            useUserStore.getState().clearUserData();
        }
    }
);