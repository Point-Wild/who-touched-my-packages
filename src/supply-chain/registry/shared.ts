/**
 * Shared utilities for registry signal computation
 */

export interface TimeSignals {
  packageAgeDays: number;
  publishedDaysAgo: number;
}

/**
 * Compute package age and published days ago from timestamps
 */
export function computeTimeSignals(createdAt: string, updatedAt: string): TimeSignals {
  const now = Date.now();
  return {
    packageAgeDays: createdAt ? Math.floor((now - new Date(createdAt).getTime()) / 86_400_000) : 0,
    publishedDaysAgo: updatedAt ? Math.floor((now - new Date(updatedAt).getTime()) / 86_400_000) : 0,
  };
}
