import { formatDomain } from '../index';
import {
  findRegistrar,
  findRegistrarUrl,
  findRegistrarIanaId,
  findCreationDate,
  findUpdatedDate,
  findExpirationDate,
  findRegistrantOrganization,
  findRegistrantCountry,
  findRegistrantEmail,
  findStatusCodes,
  findNameServers,
} from './utils/patterns';
import { getWhoisServer } from './utils/servers';
import { getCachedWhoisData, cacheWhoisData } from './utils/cache';
import { followWhoisReferrals } from './utils/query';

/**
 * Interface for WHOIS data
 */
export interface WhoisData {
  // Registration information
  registrar?: string;
  registrarUrl?: string;
  registrarIanaId?: string;

  // Dates
  creationDate?: Date;
  updatedDate?: Date;
  expirationDate?: Date;

  // Contact information (redacted in many cases due to privacy)
  registrant?: {
    organization?: string;
    country?: string;
    email?: string;
  };

  // Status codes
  statusCodes?: string[];

  // Name servers
  nameServers?: string[];

  // Raw WHOIS response
  rawText: string;
}

/**
 * Parses a raw WHOIS response into structured data
 * @param rawData The raw WHOIS response
 * @returns Parsed WHOIS data
 */
function parseWhoisData(rawData: string): WhoisData {
  const result: WhoisData = {
    rawText: rawData,
  };

  // Parse registrar info
  result.registrar = findRegistrar(rawData);
  result.registrarUrl = findRegistrarUrl(rawData);
  result.registrarIanaId = findRegistrarIanaId(rawData);

  // Parse dates
  result.creationDate = findCreationDate(rawData);
  result.updatedDate = findUpdatedDate(rawData);
  result.expirationDate = findExpirationDate(rawData);

  // Parse registrant info
  result.registrant = {
    organization: findRegistrantOrganization(rawData),
    country: findRegistrantCountry(rawData),
    email: findRegistrantEmail(rawData),
  };

  // Parse status codes
  const statusCodes = findStatusCodes(rawData);
  if (statusCodes.length > 0) {
    result.statusCodes = statusCodes;
  }

  // Parse name servers
  const nameServers = findNameServers(rawData);
  if (nameServers.length > 0) {
    result.nameServers = nameServers;
  }

  // Special handling for reserved domains like example.com
  if (rawData.includes('IANA') && rawData.includes('RESERVED')) {
    result.registrar = 'IANA (Reserved Domain)';
    if (!result.statusCodes) {
      result.statusCodes = ['RESERVED-IANA'];
    }
  }

  return result;
}

/**
 * Gets WHOIS data for a domain
 * @param domain The domain to get WHOIS data for
 * @param useCache Whether to use cached data if available
 * @param maxReferrals Maximum number of referrals to follow (to prevent infinite loops)
 * @param debug Whether to enable debug logging
 * @returns Promise resolving to WHOIS data
 */
export async function getWhoisData(
  domain: string,
  useCache = true,
  maxReferrals = 3,
  debug = false
): Promise<WhoisData> {
  const formattedDomain = formatDomain(domain);

  if (debug) {
    console.log(`\n[DEBUG] Getting WHOIS data for domain: ${formattedDomain}`);
  }

  // Check cache
  if (useCache) {
    const cached = getCachedWhoisData(formattedDomain);
    if (cached) {
      if (debug) {
        console.log('[DEBUG] Using cached WHOIS data');
      }
      return cached;
    }
  }

  try {
    // Start with the initial WHOIS server
    const initialServer = getWhoisServer(formattedDomain);
    if (debug) {
      console.log(`[DEBUG] Initial WHOIS server: ${initialServer}`);
    }

    const response = await followWhoisReferrals(
      formattedDomain,
      initialServer,
      maxReferrals,
      debug
    );

    // Parse the combined response data
    const parsedData = parseWhoisData(response);

    // Cache the result
    cacheWhoisData(formattedDomain, parsedData);

    if (debug) {
      console.log('\n[DEBUG] Parsed WHOIS data:');
      console.log(JSON.stringify(parsedData, null, 2));
    }

    return parsedData;
  } catch (error) {
    if (debug) {
      console.error('[DEBUG] Error getting WHOIS data:', error);
    }
    if (error instanceof Error) {
      throw new Error(
        `Could not fetch WHOIS data for domain ${formattedDomain}. Details: ${error.message}`
      );
    } else {
      throw new Error(`Could not fetch WHOIS data for domain ${formattedDomain}.`);
    }
  }
}
