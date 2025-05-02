// Common date patterns
const DATE_PATTERNS = {
  iso8601: /\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?/, // 2019-02-28T16:11:39Z
  simple: /\d{4}-\d{2}-\d{2}/, // 2019-02-28
  american: /\d{2}\/\d{2}\/\d{4}/, // 02/28/2019
  european: /\d{2}-\d{2}-\d{4}/, // 28-02-2019
  written: /\d{1,2}\s+[A-Za-z]+\s+\d{4}/, // 28 February 2019
  timestamp: /\d{10,}/, // Unix timestamp
};

// Creation label patterns
const CREATION_PATTERNS = [
  /Creation Date:\s*([^\n]+)/i,
  /Created on:\s*([^\n]+)/i,
  /created:\s*([^\n]+)/i,
  /Domain Registration Date:\s*([^\n]+)/i,
  /Domain Create Date:\s*([^\n]+)/i,
  /Created Date:\s*([^\n]+)/i,
  /Registered on:\s*([^\n]+)/i,
  /Registration Date:\s*([^\n]+)/i,
];

// Updated label patterns
const UPDATED_PATTERNS = [
  /Updated Date:\s*([^\n]+)/i,
  /Last Modified:\s*([^\n]+)/i,
  /Last Updated:\s*([^\n]+)/i,
  /Modified Date:\s*([^\n]+)/i,
  /Changed:\s*([^\n]+)/i,
];

// Expiration label patterns
const EXPIRATION_PATTERNS = [
  /Registry Expiry Date:\s*([^\n]+)/i,
  /Expiration Date:\s*([^\n]+)/i,
  /Registrar Registration Expiration Date:\s*([^\n]+)/i,
  /Expires on:\s*([^\n]+)/i,
  /Expiry Date:\s*([^\n]+)/i,
];

/**
 * Parses a date string using multiple formats
 * @param dateStr The date string to parse
 * @returns Parsed Date object or undefined if parsing fails
 */
function parseDateString(dateStr: string): Date | undefined {
  // Try parsing the date string directly first
  try {
    const date = new Date(dateStr);
    if (!isNaN(date.getTime())) {
      return date;
    }
  } catch {
    // Continue to pattern matching if direct parsing fails
  }

  // Try matching against known date patterns
  for (const [, pattern] of Object.entries(DATE_PATTERNS)) {
    const dateMatch = dateStr.match(pattern);
    if (dateMatch) {
      try {
        const date = new Date(dateMatch[0]);
        if (!isNaN(date.getTime())) {
          return date;
        }
      } catch {
        // Continue to next pattern if this one fails
      }
    }
  }

  return undefined;
}

/**
 * Finds a date in the raw data using the specified label patterns
 * @param rawData The raw WHOIS data
 * @param labelPatterns Array of label patterns to search for
 * @returns Parsed Date object or undefined if no date found
 */
function findDate(rawData: string, labelPatterns: RegExp[]): Date | undefined {
  for (const pattern of labelPatterns) {
    const match = rawData.match(pattern);
    if (match && match[1]) {
      const dateStr = match[1].trim();
      const date = parseDateString(dateStr);
      if (date) {
        return date;
      }
    }
  }
  return undefined;
}

/**
 * Finds the creation date in the raw WHOIS data
 * @param rawData The raw WHOIS data
 * @returns Parsed Date object or undefined if no creation date found
 */
export function findCreationDate(rawData: string): Date | undefined {
  return findDate(rawData, CREATION_PATTERNS);
}

/**
 * Finds the updated date in the raw WHOIS data
 * @param rawData The raw WHOIS data
 * @returns Parsed Date object or undefined if no updated date found
 */
export function findUpdatedDate(rawData: string): Date | undefined {
  return findDate(rawData, UPDATED_PATTERNS);
}

/**
 * Finds the expiration date in the raw WHOIS data
 * @param rawData The raw WHOIS data
 * @returns Parsed Date object or undefined if no expiration date found
 */
export function findExpirationDate(rawData: string): Date | undefined {
  return findDate(rawData, EXPIRATION_PATTERNS);
}
