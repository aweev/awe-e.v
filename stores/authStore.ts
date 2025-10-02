import { create } from 'zustand';
import { persist, createJSONStorage } from 'zustand/middleware';
import type { AuthUser } from '@/lib/auth/auth.types';
import { PermissionString } from '@/lib/audit/actions';

export interface AuthState {
  user: AuthUser | null;
  accessToken: string | null;
  isAuthenticated: boolean;
  onboardingCompleted: boolean | null;
  mfaToken: string | null;
  lastActivity: number | null;
  isRefreshing: boolean;
}

interface SetAuthPayload {
  user: AuthUser | null;
  accessToken?: string | null;
  onboardingCompleted?: boolean | null;
}


export interface AuthActions {
  setAuth: (payload: SetAuthPayload) => void;
  setMfaToken: (token: string | null) => void;
  logout: () => Promise<void>;
  setOnboardingCompleted: () => void;
  updateLastActivity: () => void;
  setRefreshing: (isRefreshing: boolean) => void;
  updateUser: (updates: Partial<AuthUser>) => void;
  hasPermission: (permission: PermissionString) => boolean;
  hasRole: (role: string) => boolean;
  clearMfaToken: () => void;
}

export type AuthStore = AuthState & {
  actions: AuthActions;
};

const initialState: AuthState = {
  user: null,
  accessToken: null,
  isAuthenticated: false,
  mfaToken: null,
  onboardingCompleted: null,
  lastActivity: null,
  isRefreshing: false,
};

export const useAuthStore = create<AuthStore>()(persist(
  (set, get) => ({
    ...initialState,
    actions: {
      setAuth: (payload) => {
        const { user, accessToken, onboardingCompleted } = payload;
        const isAuthenticated = !!user && !!accessToken;
        set({
          user,
          accessToken: accessToken ?? null,
          isAuthenticated,
          onboardingCompleted: onboardingCompleted ?? null,
          mfaToken: null,
          lastActivity: isAuthenticated ? Date.now() : null,
          isRefreshing: false,
        });
      },

      setMfaToken: (token) => set({ mfaToken: token }),
      clearMfaToken: () => set({ mfaToken: null }),

      logout: async () => {
        const { isRefreshing } = get();
        if (isRefreshing) return;

        set({ isRefreshing: true });

        try {
          await fetch('/api/auth/logout', { method: 'POST' });
        } catch (error) {
          console.error('Failed to logout from server:', error);
        } finally {
          set({ ...initialState, actions: get().actions });
        }
      },

      setOnboardingCompleted: () => {
        const { user } = get();
        if (user) {
          set({
            user: { ...user, onboardingCompleted: true },
            onboardingCompleted: true,
          });
        }
      },

      updateLastActivity: () => {
        const { isAuthenticated } = get();
        if (isAuthenticated) {
          set({ lastActivity: Date.now() });
        }
      },

      setRefreshing: (isRefreshing) => set({ isRefreshing }),

      updateUser: (updates) => {
        const { user } = get();
        if (user) {
          set({ user: { ...user, ...updates } });
        }
      },

      hasPermission: (permission) => {
        const { user } = get();
        return user?.permissions?.includes(permission) ?? false;
      },

      hasRole: (roleName) => {
        const { user } = get();
        return user?.roles?.includes(roleName as any) ?? false;
      },
    },
  }),
  {
    name: 'auth-storage',
    storage: createJSONStorage(() => localStorage),
    partialize: (state) => ({
      user: state.user,
      accessToken: state.accessToken,
      isAuthenticated: state.isAuthenticated,
      onboardingCompleted: state.onboardingCompleted,
      lastActivity: state.lastActivity,
    }),
    version: 1,
  }
)
);