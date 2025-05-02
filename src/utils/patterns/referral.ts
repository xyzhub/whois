/**
 * Patterns for finding WHOIS server referrals in WHOIS responses
 */
export const REFERRAL_PATTERNS = [
  /Registrar WHOIS Server:\s*(.+?)(?:\n|$)/i,
  /WHOIS Server:\s*(.+?)(?:\n|$)/i,
  /Referral URL:\s*(?:https?:\/\/)?(?:www\.)?(.+?)(?:\/|\n|$)/i,
  /refer:\s*(.+?)(?:\n|$)/i,
];

/**
 * Finds a WHOIS server referral in the raw WHOIS data
 * @param rawData The raw WHOIS data
 * @param currentServer The current WHOIS server being queried
 * @returns The referral server hostname or undefined if no referral found
 */
export function findReferralServer(rawData: string, currentServer: string): string | undefined {
  for (const pattern of REFERRAL_PATTERNS) {
    const match = rawData.match(pattern);
    if (
      match &&
      match[1] &&
      match[1].trim() &&
      match[1].includes('.') &&
      match[1] !== currentServer
    ) {
      // Clean up the server name (remove http://, www., etc.)
      const nextServer = match[1]
        .trim()
        .replace(/^https?:\/\//i, '')
        .replace(/^www\./i, '');

      // Don't follow if we're already at this server
      if (nextServer && nextServer !== currentServer) {
        return nextServer;
      }
    }
  }
  return undefined;
}
