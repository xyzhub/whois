export const STATUS_PATTERNS = [/Domain Status:\s*(.+?)(?:\n|$)/gi, /Status:\s*(.+?)(?:\n|$)/gi];

export const NAMESERVER_PATTERNS = [
  /Name Server:\s*(.+?)(?:\n|$)/gi,
  /Nameserver:\s*(.+?)(?:\n|$)/gi,
  /nserver:\s*(.+?)(?:\n|$)/gi,
];

export function findStatusCodes(rawData: string): string[] {
  const statusCodes: string[] = [];

  for (const pattern of STATUS_PATTERNS) {
    let statusMatch: RegExpExecArray | null;
    while ((statusMatch = pattern.exec(rawData)) !== null) {
      const status = statusMatch[1].trim();
      if (status && !statusCodes.includes(status)) {
        statusCodes.push(status);
      }
    }
  }

  return statusCodes;
}

export function findNameServers(rawData: string): string[] {
  const nameServers: string[] = [];

  for (const pattern of NAMESERVER_PATTERNS) {
    let nsMatch: RegExpExecArray | null;
    while ((nsMatch = pattern.exec(rawData)) !== null) {
      const server = nsMatch[1].trim().toLowerCase();
      if (server && !nameServers.includes(server)) {
        nameServers.push(server);
      }
    }
  }

  return nameServers;
}
