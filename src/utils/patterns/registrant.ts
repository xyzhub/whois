export const REGISTRANT_ORG_PATTERNS = [
  /Registrant Organization:\s*(.+?)(?:\n|$)/i,
  /Registrant:\s*(.+?)(?:\n|$)/i,
  /Organization:\s*(.+?)(?:\n|$)/i,
];

export const REGISTRANT_COUNTRY_PATTERNS = [
  /Registrant Country:\s*(.+?)(?:\n|$)/i,
  /Country:\s*(.+?)(?:\n|$)/i,
];

export const REGISTRANT_EMAIL_PATTERNS = [
  /Registrant Email:\s*(.+?)(?:\n|$)/i,
  /Email:\s*(.+?)(?:\n|$)/i,
];

export function findRegistrantOrganization(rawData: string): string | undefined {
  for (const pattern of REGISTRANT_ORG_PATTERNS) {
    const match = rawData.match(pattern);
    if (match && match[1].trim() && !match[1].includes('REDACTED FOR PRIVACY')) {
      return match[1].trim();
    }
  }
  return undefined;
}

export function findRegistrantCountry(rawData: string): string | undefined {
  for (const pattern of REGISTRANT_COUNTRY_PATTERNS) {
    const match = rawData.match(pattern);
    if (match && match[1].trim()) {
      return match[1].trim();
    }
  }
  return undefined;
}

export function findRegistrantEmail(rawData: string): string | undefined {
  // Don't extract email if GDPR protected
  if (rawData.includes('GDPR') || rawData.includes('REDACTED FOR PRIVACY')) {
    return undefined;
  }

  for (const pattern of REGISTRANT_EMAIL_PATTERNS) {
    const match = rawData.match(pattern);
    if (match && match[1].trim() && match[1].includes('@')) {
      return match[1].trim();
    }
  }
  return undefined;
}
