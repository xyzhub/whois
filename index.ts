import * as https from 'https';
import * as http from 'http';
import { Socket } from 'net';
import * as dns from 'dns';
import { WhoisData } from './src/whois';
import logger from './src/utils/logger';

// Custom interface for the socket object
interface CustomSocket extends Socket {
  getPeerCertificate(detailed: boolean): CertificateData;
}

// Interface for certificate data
interface CertificateData {
  subject: { [key: string]: string | string[] };
  issuer: { [key: string]: string | string[] };
  valid_from: string;
  valid_to: string;
  raw?: Buffer;
  fingerprint?: string;
  fingerprint256?: string;
  serialNumber?: string;
  issuerCertificate?: CertificateData;
  [key: string]: unknown;
}

// SSL data structure
interface SslData {
  subject: { [key: string]: string | string[] };
  issuer: { [key: string]: string | string[] };
  valid: boolean;
  validFrom: number;
  validTo: number;
  // New fields for PEM certificates
  certificate?: string;
  intermediateCertificate?: string;
  rootCertificate?: string;
  // New field for readable details
  details?: {
    issuer: string;
    subject: string;
    validFrom: Date;
    validTo: Date;
  };
}

// DomainInfo interface to describe the return type of fetchDomainInfo function
interface DomainInfo {
  sslData: SslData;
  serverData: string | undefined;
  dnsData:
    | {
        A: string[];
        CNAME: string | null;
        TXT: string[];
        MX: Array<{ exchange: string; priority: number }>;
        NS: string[];
        SOA: dns.SoaRecord | null;
      }
    | undefined;
  httpStatus: number | undefined;
  // New WHOIS data field for version 2.3.0
  whoisData?: WhoisData;
}

// Options for configuring the fetch request
export interface RequestOptions {
  /** Timeout in milliseconds for HTTP requests */
  timeout?: number;
  /** Custom headers to include in HTTP requests */
  headers?: Record<string, string>;
  /** Whether to follow redirects in HTTP requests */
  followRedirects?: boolean;
  /** Maximum number of redirects to follow */
  maxRedirects?: number;
  debug?: boolean;
}

// Default request options
const DEFAULT_OPTIONS: RequestOptions = {
  timeout: 10000, // 10 seconds
  followRedirects: true,
  maxRedirects: 5,
};

// Default SSL data structure
const DEFAULT_SSL_DATA: SslData = {
  subject: {},
  issuer: {},
  valid: false,
  validFrom: 0,
  validTo: 0,
  details: {
    subject: '',
    issuer: 'No SSL Certificate',
    validFrom: new Date(0),
    validTo: new Date(0),
  },
};

/**
 * Formats a given domain to `example.com` format.
 * @param domain The domain to format.
 * @returns The formatted domain.
 */
export function formatDomain(domain: string): string {
  return domain
    .replace(/^(https?:\/\/)?(www\.)?/i, '')
    .replace(/\/$/, '')
    .toLowerCase();
}

/**
 * Extracts the subdomain from a given domain.
 * @param domain The domain to extract the subdomain from.
 * @returns The subdomain or null if no subdomain is present.
 */
export function extractSubdomain(domain: string): string | null {
  const formattedDomain = formatDomain(domain);
  const parts = formattedDomain.split('.');

  // Check if there are more than 2 parts (e.g., sub.example.com)
  if (parts.length > 2) {
    return parts[0];
  }

  return null;
}

/**
 * Gets the root domain (e.g., example.com) from a domain that may include a subdomain.
 * @param domain The domain to extract the root domain from.
 * @returns The root domain.
 */
export function getRootDomain(domain: string): string {
  const formattedDomain = formatDomain(domain);
  const parts = formattedDomain.split('.');

  // If domain has more than 2 parts, return the last two (e.g., example.com from sub.example.com)
  if (parts.length > 2) {
    return parts.slice(-2).join('.');
  }

  return formattedDomain;
}

/**
 * Checks if the given domain is valid.
 * @param domain The domain to check.
 * @returns True if the domain is valid, false otherwise.
 */
export const checkDomain = (domain: string): boolean => {
  const domainParts = domain.split('.');
  return domainParts.length > 1 && domainParts[0].length > 0;
};

/**
 * converts a date string to a timestamp
 * @param dateString
 * @returns timestamp
 */
export function dateToTimestamp(dateString: string): number {
  return new Date(dateString).getTime();
}

/**
 * Extracts SSL data from the given certificate.
 * @param cert The certificate object
 * @returns An object containing the SSL data.
 */
function extractSslData(cert: CertificateData): SslData {
  const validToTimestamp = dateToTimestamp(cert.valid_to);
  const validFromTimestamp = dateToTimestamp(cert.valid_from);

  // Extract human-readable subject and issuer information
  const subjectCN =
    typeof cert.subject?.CN === 'string'
      ? cert.subject.CN
      : typeof cert.subject?.commonName === 'string'
        ? cert.subject.commonName
        : Array.isArray(cert.subject?.CN)
          ? cert.subject.CN.join(', ')
          : Object.values(cert.subject || {})
              .map((v) => (Array.isArray(v) ? v.join(', ') : v))
              .join(', ');

  // Prioritize Organization (O) for issuer information, falling back to CN if not available
  const issuerCN =
    typeof cert.issuer?.O === 'string'
      ? cert.issuer.O
      : typeof cert.issuer?.organizationName === 'string'
        ? cert.issuer.organizationName
        : typeof cert.issuer?.CN === 'string'
          ? cert.issuer.CN
          : typeof cert.issuer?.commonName === 'string'
            ? cert.issuer.commonName
            : Array.isArray(cert.issuer?.O)
              ? cert.issuer.O.join(', ')
              : Array.isArray(cert.issuer?.CN)
                ? cert.issuer.CN.join(', ')
                : Object.values(cert.issuer || {})
                    .map((v) => (Array.isArray(v) ? v.join(', ') : v))
                    .join(', ');

  // Extract certificates in PEM format if available
  let certificate: string | undefined = undefined;
  let intermediateCertificate: string | undefined = undefined;
  let rootCertificate: string | undefined = undefined;

  try {
    // The main certificate PEM
    if (cert.raw) {
      certificate = `-----BEGIN CERTIFICATE-----\n${cert.raw
        .toString('base64')
        .match(/.{1,64}/g)
        ?.join('\n')}\n-----END CERTIFICATE-----`;
    }

    // Try to extract intermediate and root certificates if available
    if (cert.issuerCertificate) {
      const intermediate = cert.issuerCertificate;
      if (intermediate.raw) {
        intermediateCertificate = `-----BEGIN CERTIFICATE-----\n${intermediate.raw
          .toString('base64')
          .match(/.{1,64}/g)
          ?.join('\n')}\n-----END CERTIFICATE-----`;
      }

      // Root certificate (if chain available)
      if (intermediate.issuerCertificate && intermediate.issuerCertificate.raw) {
        rootCertificate = `-----BEGIN CERTIFICATE-----\n${intermediate.issuerCertificate.raw
          .toString('base64')
          .match(/.{1,64}/g)
          ?.join('\n')}\n-----END CERTIFICATE-----`;
      }
    }
  } catch {
    // Silently handle certificate extraction errors
    // This ensures backward compatibility - if certificate extraction fails,
    // we'll still return the existing fields
  }

  return {
    // Original fields (for backward compatibility)
    subject: cert.subject,
    issuer: cert.issuer,
    valid: validToTimestamp > Date.now(),
    validFrom: validFromTimestamp,
    validTo: validToTimestamp,

    // New certificate fields
    certificate,
    intermediateCertificate,
    rootCertificate,

    // Human-readable details
    details: {
      subject: subjectCN,
      issuer: issuerCN,
      validFrom: new Date(validFromTimestamp),
      validTo: new Date(validToTimestamp),
    },
  };
}

/**
 * Validates a domain name and throws an appropriate error if invalid
 */
function validateDomain(domain: string): void {
  if (!domain) {
    throw new Error('Domain name cannot be empty');
  }
  if (!checkDomain(domain)) {
    throw new Error('Invalid domain name format');
  }
}

/**
 * Fetches SSL, server, and DNS data for the given domain.
 * @param domain The domain to fetch the information for.
 * @param options Optional request configuration
 * @returns A Promise that resolves to an object containing the SSL, server, and DNS data.
 */
export async function fetchDomainInfo(
  domain: string,
  options: RequestOptions = {}
): Promise<DomainInfo | undefined> {
  const { debug = false } = options;
  const mergedOptions = { ...DEFAULT_OPTIONS, ...options };

  validateDomain(domain);
  const formattedDomain = formatDomain(domain);

  try {
    // Initialize result object with default values
    const result: DomainInfo = {
      sslData: {
        ...DEFAULT_SSL_DATA,
        details: {
          ...DEFAULT_SSL_DATA.details,
          subject: formattedDomain,
          issuer: 'No SSL Certificate',
          validFrom: new Date(0),
          validTo: new Date(0),
        },
      },
      serverData: undefined,
      dnsData: undefined,
      httpStatus: undefined,
      whoisData: undefined,
    };

    // Fetch WHOIS data first since it's most reliable
    logger.logInfo(debug, 'Getting WHOIS data', `for domain: ${formattedDomain}`);
    try {
      result.whoisData = await import('./src/whois')
        .then((whoisModule) => whoisModule.getWhoisData(formattedDomain, true, 3, debug))
        .catch((error) => {
          logger.logWarning(debug, 'WHOIS data fetch', error.message);
          return undefined;
        });
    } catch (error) {
      logger.logError(debug, 'WHOIS data', error);
    }

    // Then fetch DNS data
    logger.logInfo(debug, 'Getting DNS data', `for domain: ${formattedDomain}`);
    try {
      result.dnsData = await getDnsData(formattedDomain);
    } catch (error) {
      logger.logError(debug, 'DNS data', error);
    }

    // Finally fetch SSL and server data
    logger.logInfo(debug, 'Getting SSL and server data', `for domain: ${formattedDomain}`);
    try {
      const [sslData, serverData, httpStatus] = await Promise.all([
        getSslData(formattedDomain, mergedOptions),
        getServerData(formattedDomain, mergedOptions),
        getHttpStatus(formattedDomain, mergedOptions),
      ]);
      result.sslData = sslData;
      result.serverData = serverData;
      result.httpStatus = httpStatus;
    } catch (error) {
      logger.logError(debug, 'SSL/server data', error);
    }

    return result;
  } catch (error) {
    logger.logError(debug, 'domain info', error);
    throw error;
  }
}

/**
 * Retrieves SSL data for the given domain.
 * @param domain The domain to fetch the SSL data for.
 * @param options Request configuration options
 * @returns A Promise that resolves to an object containing the SSL data.
 */
async function getSslData(
  domain: string,
  options: RequestOptions = DEFAULT_OPTIONS
): Promise<SslData> {
  return new Promise((resolve, reject) => {
    // First try HTTPS with modern protocols
    const req = https
      .request(
        `https://${domain}`,
        {
          method: 'HEAD',
          timeout: options.timeout,
          headers: options.headers || {},
          secureProtocol: 'TLSv1_2_method', // Default to TLS 1.2
        },
        (res) => {
          const socket = res.socket as CustomSocket;
          const cert = socket.getPeerCertificate(true);
          resolve(extractSslData(cert));
          socket.destroy();
        }
      )
      .on('error', (error: NodeJS.ErrnoException) => {
        // If HTTPS fails with EPROTO, try with older protocols
        if (error.code === 'EPROTO') {
          const legacyReq = https
            .request(
              `https://${domain}`,
              {
                method: 'HEAD',
                timeout: options.timeout,
                headers: options.headers || {},
                secureProtocol: 'TLSv1_method', // Try TLS 1.0
              },
              (legacyRes) => {
                const socket = legacyRes.socket as CustomSocket;
                const cert = socket.getPeerCertificate(true);
                resolve(extractSslData(cert));
                socket.destroy();
              }
            )
            .on('error', (legacyError: NodeJS.ErrnoException) => {
              // If both modern and legacy protocols fail, try HTTP
              if (legacyError.code === 'EPROTO' || legacyError.code === 'ECONNREFUSED') {
                const httpReq = http
                  .request(
                    `http://${domain}`,
                    {
                      method: 'HEAD',
                      timeout: options.timeout,
                      headers: options.headers || {},
                    },
                    (httpRes) => {
                      // For HTTP, return a basic SSL data object indicating no SSL
                      resolve({
                        subject: {},
                        issuer: {},
                        valid: false,
                        validFrom: 0,
                        validTo: 0,
                        details: {
                          subject: domain,
                          issuer: 'No SSL Certificate',
                          validFrom: new Date(0),
                          validTo: new Date(0),
                        },
                      });
                      httpRes.socket?.destroy();
                    }
                  )
                  .on('error', (httpError: NodeJS.ErrnoException) => {
                    reject(httpError);
                  });

                httpReq.end();
              } else {
                reject(legacyError);
              }
            });

          legacyReq.end();
        } else if (error.code === 'ECONNREFUSED') {
          // If connection refused, try HTTP
          const httpReq = http
            .request(
              `http://${domain}`,
              {
                method: 'HEAD',
                timeout: options.timeout,
                headers: options.headers || {},
              },
              (httpRes) => {
                // For HTTP, return a basic SSL data object indicating no SSL
                resolve({
                  subject: {},
                  issuer: {},
                  valid: false,
                  validFrom: 0,
                  validTo: 0,
                  details: {
                    subject: domain,
                    issuer: 'No SSL Certificate',
                    validFrom: new Date(0),
                    validTo: new Date(0),
                  },
                });
                httpRes.socket?.destroy();
              }
            )
            .on('error', (httpError: NodeJS.ErrnoException) => {
              reject(httpError);
            });

          httpReq.end();
        } else {
          reject(error);
        }
      });

    req.end();
  });
}

/**
 * Retrieves server data for the given domain.
 * @param domain The domain to fetch the server data for.
 * @param options Request configuration options
 * @returns A Promise that resolves to a string containing the server data.
 */
async function getServerData(
  domain: string,
  options: RequestOptions = DEFAULT_OPTIONS
): Promise<string | undefined> {
  return new Promise((resolve, reject) => {
    // First try HTTPS
    const req = https
      .request(
        `https://${domain}`,
        {
          method: 'HEAD',
          timeout: options.timeout,
          headers: options.headers || {},
          agent: false, // Disable connection pooling
        },
        (res) => {
          const serverHeaderValue = res.headers['server'];
          const result = Array.isArray(serverHeaderValue)
            ? serverHeaderValue[0]
            : serverHeaderValue;

          // Ensure socket is destroyed
          if (res.socket) {
            res.socket.destroy();
          }

          resolve(result);
        }
      )
      .on('error', (error: NodeJS.ErrnoException) => {
        // If HTTPS fails, try HTTP
        if (error.code === 'EPROTO' || error.code === 'ECONNREFUSED') {
          const httpReq = http
            .request(
              `http://${domain}`,
              {
                method: 'HEAD',
                timeout: options.timeout,
                headers: options.headers || {},
                agent: false, // Disable connection pooling
              },
              (httpRes) => {
                const serverHeaderValue = httpRes.headers['server'];
                const result = Array.isArray(serverHeaderValue)
                  ? serverHeaderValue[0]
                  : serverHeaderValue;

                // Ensure socket is destroyed
                if (httpRes.socket) {
                  httpRes.socket.destroy();
                }

                resolve(result);
              }
            )
            .on('error', (httpError) => {
              reject(httpError);
            });

          httpReq.end();
        } else {
          reject(error);
        }
      });

    req.end();
  });
}

/**
 * Retrieves DNS data for the given domain.
 * @param domain The domain to fetch the DNS data for.
 * @returns A Promise that resolves to an object containing the DNS data.
 */
async function getDnsData(domain: string): Promise<{
  A: string[];
  CNAME: string | null;
  TXT: string[];
  MX: Array<{ exchange: string; priority: number }>;
  NS: string[];
  SOA: dns.SoaRecord | null;
}> {
  const subdomain = extractSubdomain(domain);
  const rootDomain = getRootDomain(domain);

  // For a subdomain, we primarily want A and CNAME records of the subdomain itself
  if (subdomain) {
    try {
      const A = await getARecords(domain);
      const CNAME = await getCNameRecord(domain);

      // For other DNS records, we typically want the root domain information
      const TXT = await getTxtRecords(rootDomain);
      const MX = await getMxRecords(rootDomain);
      const NS = await getNsRecords(rootDomain);
      const SOA = await getSoaRecord(rootDomain);

      return { A, CNAME, TXT, MX, NS, SOA };
    } catch (error) {
      // If looking up the subdomain fails, fall back to the root domain
      console.error(
        `Error fetching subdomain DNS data: ${
          error instanceof Error ? error.message : String(error)
        }`
      );
      console.log(`Falling back to root domain ${rootDomain}`);
    }
  }

  // Standard lookup for root domain or fallback
  const A = await getARecords(domain);
  const CNAME = await getCNameRecord(domain);
  const TXT = await getTxtRecords(domain);
  const MX = await getMxRecords(domain);
  const NS = await getNsRecords(domain);
  const SOA = await getSoaRecord(domain);

  return { A, CNAME, TXT, MX, NS, SOA };
}

/**
 * Retrieves A records for the given domain.
 * @param domain The domain to fetch the A records for.
 * @returns A Promise that resolves to an array of strings containing the A records.
 */
function getARecords(domain: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    dns.resolve4(domain, (error, addresses) => {
      if (error) {
        reject(error);
      } else {
        resolve(addresses);
      }
    });
  });
}

/**
 * Retrieves CNAME record for the given domain.
 * @param domain The domain to fetch the CNAME record for.
 * @returns A Promise that resolves to a string containing the CNAME record.
 */
function getCNameRecord(domain: string): Promise<string | null> {
  return new Promise((resolve, reject) => {
    dns.resolveCname(domain, (error, addresses) => {
      if (error) {
        if (error.code === 'ENODATA') {
          resolve(null);
        } else {
          reject(error);
        }
      } else {
        resolve(addresses[0]);
      }
    });
  });
}

/**
 * Retrieves TXT records for the given domain.
 * @param domain The domain to fetch the TXT records for.
 * @returns A Promise that resolves to an array of strings containing the TXT records.
 */
function getTxtRecords(domain: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    dns.resolveTxt(domain, (error, records) => {
      if (error) {
        reject(error);
      } else {
        const flattenedRecords = records.flat();
        resolve(flattenedRecords);
      }
    });
  });
}

/**
 * Retrieves MX records for the given domain.
 * @param domain The domain to fetch the MX records for.
 * @returns A Promise that resolves to an array of objects containing the MX records.
 */
function getMxRecords(domain: string): Promise<Array<{ exchange: string; priority: number }>> {
  return new Promise((resolve, reject) => {
    dns.resolveMx(domain, (error, records) => {
      if (error) {
        reject(error);
      } else {
        resolve(records);
      }
    });
  });
}

/**
 * Retrieves NS records for the given domain.
 * @param domain The domain to fetch the NS records for.
 * @returns A Promise that resolves to an array of strings containing the NS records.
 */
function getNsRecords(domain: string): Promise<string[]> {
  return new Promise((resolve, reject) => {
    dns.resolveNs(domain, (error, records) => {
      if (error) {
        reject(error);
      } else {
        resolve(records);
      }
    });
  });
}

/**
 * Retrieves SOA record for the given domain.
 * @param domain The domain to fetch the SOA record for.
 * @returns A Promise that resolves to an object containing the SOA record.
 */
function getSoaRecord(domain: string): Promise<dns.SoaRecord | null> {
  return new Promise((resolve, reject) => {
    dns.resolveSoa(domain, (error, record) => {
      if (error) {
        if (error.code === 'ENODATA') {
          resolve(null);
        } else {
          reject(error);
        }
      } else {
        resolve(record);
      }
    });
  });
}

/**
 * Retrieves HTTP status for the given domain.
 * @param domain The domain to fetch the HTTP status for.
 * @param options Request configuration options
 * @returns A Promise that resolves to a number containing the HTTP status.
 */
async function getHttpStatus(
  domain: string,
  options: RequestOptions = DEFAULT_OPTIONS
): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = https
      .request(
        `https://${domain}`,
        {
          method: 'HEAD',
          timeout: options.timeout,
          headers: options.headers || {},
          agent: false, // Disable connection pooling
        },
        (res) => {
          const statusCode = res.statusCode || 0;

          // Ensure socket is destroyed
          if (res.socket) {
            res.socket.destroy();
          }

          resolve(statusCode);
        }
      )
      .on('error', (error) => {
        reject(error);
      });

    req.end();
  });
}

// Export WhoisData interface for users
export { WhoisData } from './src/whois';
