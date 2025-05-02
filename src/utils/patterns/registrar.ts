export const REGISTRAR_PATTERNS = [
  /Registrar:\s*(.+?)(?:\n|$)/i,
  /Registrar Name:\s*(.+?)(?:\n|$)/i,
  /Sponsoring Registrar:\s*(.+?)(?:\n|$)/i,
  /Registration Service Provider:\s*(.+?)(?:\n|$)/i,
];

export const URL_PATTERNS = [
  /Registrar URL:\s*(.+?)(?:\n|$)/i,
  /URL:\s*(.+?)(?:\n|$)/i,
  /Registrar Website:\s*(.+?)(?:\n|$)/i,
];

export const IANA_ID_PATTERN = /Registrar IANA ID:\s*(.+?)(?:\n|$)/i;

export function findRegistrar(rawData: string): string | undefined {
  for (const pattern of REGISTRAR_PATTERNS) {
    const match = rawData.match(pattern);
    if (match && match[1].trim()) {
      return match[1].trim();
    }
  }

  // Special case for MarkMonitor
  if (rawData.includes('MarkMonitor')) {
    return 'MarkMonitor Inc.';
  }

  // Try to extract from any line that has "Registrar:" followed by text on the same line
  const lines = rawData.split('\n');
  for (const line of lines) {
    if (
      line.includes('Registrar:') &&
      !line.includes('WHOIS Server') &&
      !line.includes('URL') &&
      !line.includes('IANA ID')
    ) {
      const parts = line.split('Registrar:');
      if (parts.length > 1 && parts[1].trim()) {
        return parts[1].trim();
      }
    }
  }

  return undefined;
}

export function findRegistrarUrl(rawData: string): string | undefined {
  for (const pattern of URL_PATTERNS) {
    const match = rawData.match(pattern);
    if (match && match[1].trim()) {
      return match[1].trim();
    }
  }
  return undefined;
}

export function findRegistrarIanaId(rawData: string): string | undefined {
  const match = rawData.match(IANA_ID_PATTERN);
  if (match && match[1].trim()) {
    return match[1].trim();
  }
  return undefined;
}
