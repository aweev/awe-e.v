import { createHash } from 'crypto';

export function isUserInRollout(
    flagKey: string,
    userId: string | undefined | null,
    percentage: number
): boolean {
    if (!userId) {
        return false;
    }

    if (percentage <= 0) return false;
    if (percentage >= 100) return true;

    const hash = createHash('sha256').update(`${flagKey}:${userId}`).digest('hex');

    const value = parseInt(hash.substring(0, 4), 16);

    const normalizedValue = value % 100;

    return normalizedValue < percentage;
}