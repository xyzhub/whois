import { WhoisData } from '../whois';

const CACHE_TTL = 3600000; // 1 hour cache
const whoisCache = new Map<string, { data: WhoisData; timestamp: number }>();

/**
 * Gets cached WHOIS data if available and not expired
 * @param domain The domain to get cached data for
 * @returns Cached WHOIS data or undefined if not available or expired
 */
export function getCachedWhoisData(domain: string): WhoisData | undefined {
  const cached = whoisCache.get(domain);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  return undefined;
}

/**
 * Caches WHOIS data for a domain
 * @param domain The domain to cache data for
 * @param data The WHOIS data to cache
 */
export function cacheWhoisData(domain: string, data: WhoisData): void {
  whoisCache.set(domain, {
    data,
    timestamp: Date.now(),
  });
}

/**
 * Clears the WHOIS cache
 */
export function clearWhoisCache(): void {
  whoisCache.clear();
}
