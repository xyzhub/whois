/**
 * Mapping of TLDs to their WHOIS servers
 *
 * This mapping contains WHOIS servers for various TLDs (Top-Level Domains).
 * The servers are organized into several categories:
 * - Generic TLDs (gTLDs) like .com, .net, .org
 * - Sponsored TLDs like .edu, .gov, .mil
 * - Country Code TLDs (ccTLDs) like .uk, .de, .fr
 * - New gTLDs like .app, .dev, .page
 *
 * Each entry maps a TLD to its corresponding WHOIS server.
 * The 'default' entry is used as a fallback when no specific server is found.
 */
export const WHOIS_SERVERS: Record<string, string> = {
  // Generic Top-Level Domains (gTLDs)
  com: 'whois.verisign-grs.com',
  net: 'whois.verisign-grs.com',
  org: 'whois.pir.org',
  info: 'whois.afilias.net',
  biz: 'whois.nic.biz',
  name: 'whois.nic.name',
  pro: 'whois.registrypro.pro',

  // Sponsored Top-Level Domains (sTLDs)
  edu: 'whois.educause.edu',
  gov: 'whois.dotgov.gov',
  int: 'whois.iana.org',
  mil: 'whois.nic.mil',
  aero: 'whois.aero',
  coop: 'whois.nic.coop',
  museum: 'whois.museum',
  mobi: 'whois.dotmobiregistry.net',
  cat: 'whois.cat',
  jobs: 'whois.nic.jobs',
  tel: 'whois.nic.tel',
  travel: 'whois.nic.travel',
  xxx: 'whois.nic.xxx',
  asia: 'whois.nic.asia',
  post: 'whois.dotpostregistry.net',

  // Regional TLDs
  eu: 'whois.eu',

  // Country Code Top-Level Domains (ccTLDs)
  uk: 'whois.nic.uk',
  au: 'whois.auda.org.au',
  ca: 'whois.cira.ca',
  de: 'whois.denic.de',
  fr: 'whois.nic.fr',
  it: 'whois.nic.it',
  jp: 'whois.jprs.jp',
  nl: 'whois.domain-registry.nl',
  nz: 'whois.srs.net.nz',
  ru: 'whois.tcinet.ru',
  se: 'whois.iis.se',
  ch: 'whois.nic.ch',
  cn: 'whois.cnnic.cn',
  in: 'whois.registry.in',
  br: 'whois.registro.br',
  mx: 'whois.mx',
  ar: 'whois.nic.ar',
  cl: 'whois.nic.cl',
  co: 'whois.nic.co',
  pe: 'kero.yachay.pe',
  ve: 'whois.nic.ve',
  za: 'whois.registry.net.za',

  // New gTLDs (added in 2012 and later)
  // These are managed by Google Registry
  app: 'whois.nic.google',
  dev: 'whois.nic.google',
  page: 'whois.nic.google',
  new: 'whois.nic.google',

  // Default fallback server
  // Used when no specific WHOIS server is found for a TLD
  default: 'whois.iana.org',
};

/**
 * Gets the appropriate WHOIS server for a domain
 *
 * This function extracts the TLD from the domain and returns the corresponding
 * WHOIS server from the WHOIS_SERVERS mapping. If no specific server is found
 * for the TLD, it returns the default WHOIS server (whois.iana.org).
 *
 * @param domain The domain to get the WHOIS server for
 * @returns The WHOIS server hostname
 */
export function getWhoisServer(domain: string): string {
  // Extract the TLD from the domain
  const tld = domain.split('.').pop()?.toLowerCase() || '';

  // Return the corresponding WHOIS server or the default server
  return WHOIS_SERVERS[tld] || WHOIS_SERVERS.default;
}
