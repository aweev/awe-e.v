import NodeCache from 'node-cache';
import { prisma } from '@/lib/db';
import type { FeatureFlag } from '@prisma/client';
import {
    type FeatureFlagKey,
    type FlagEvaluationContext,
    flagDefinitions,
} from './flag-definitions';
import { isUserInRollout } from './rollout-strategy';

const flagCache = new NodeCache({
    stdTTL: 300,
    checkperiod: 60,
});

const ALL_FLAGS_CACHE_KEY = 'all_active_feature_flags';

class FeatureFlagService {
    private async getFlagsFromCache(): Promise<Map<FeatureFlagKey, FeatureFlag>> {
        let flagsMap = flagCache.get<Map<FeatureFlagKey, FeatureFlag>>(ALL_FLAGS_CACHE_KEY);

        if (!flagsMap) {
            console.log('[FF-CACHE-MISS] Hydrating feature flag cache from database.');
            const allFlagsFromDb = await prisma.featureFlag.findMany({
                where: { isActive: true },
            });

            flagsMap = new Map(allFlagsFromDb.map((flag) => [flag.key as FeatureFlagKey, flag]));
            flagCache.set(ALL_FLAGS_CACHE_KEY, flagsMap);
        }

        return flagsMap;
    }

    public async isEnabled(
        key: FeatureFlagKey,
        context: FlagEvaluationContext = {}
    ): Promise<boolean> {
        const flags = await this.getFlagsFromCache();
        const flag = flags.get(key);

        if (!flag) {
            return flagDefinitions[key].defaultValue;
        }
        if (context.userId && flag.allowedUserIds.includes(context.userId)) {
            return true;
        }

        if (context.roles?.some(role => flag.allowedRoles.includes(role))) {
            return true;
        }

        if (flag.rolloutPercentage > 0) {
            if (isUserInRollout(key, context.userId, flag.rolloutPercentage)) {
                return true;
            }
        }

        return false;
    }

    public flushCache(): void {
        flagCache.flushAll();
        console.log('[FF-CACHE-FLUSH] Feature flag cache has been cleared.');
    }
}

export const featureFlagService = new FeatureFlagService();