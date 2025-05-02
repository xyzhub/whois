import { Socket } from 'net';
import * as tls from 'tls';
import * as dns from 'dns';
import { findReferralServer } from './patterns/referral';
import logger from './logger';

/**
 * Queries a WHOIS server for domain information
 * @param domain The domain to query
 * @param server The WHOIS server to query
 * @param timeout Timeout in milliseconds
 * @param debug Whether to enable debug logging
 * @returns Promise resolving to the raw WHOIS response
 */
export async function queryWhoisServer(
  domain: string,
  server: string,
  timeout = 10000,
  debug = false
): Promise<string> {
  return new Promise((resolve, reject) => {
    logger.logInfo(debug, 'Querying WHOIS server', `${server} for domain ${domain}`);

    try {
      // Resolve the WHOIS server hostname to an IP address
      dns.lookup(server, (err, address) => {
        if (err) {
          logger.logError(debug, 'DNS lookup', err);
          reject(new Error(`Failed to resolve WHOIS server: ${err.message}`));
          return;
        }

        // First try with TLS
        const tlsSocket = tls.connect({
          host: server,
          port: 43,
          rejectUnauthorized: false, // Allow self-signed certificates
          servername: server, // SNI support
        });

        let data = '';
        let triedPlain = false;

        tlsSocket.setTimeout(timeout);

        tlsSocket.on('timeout', () => {
          logger.logError(debug, 'WHOIS query', 'Connection timeout');
          tlsSocket.destroy();
          reject(new Error('Connection timeout'));
        });

        tlsSocket.on('error', (error: Error) => {
          if (!triedPlain && error.message.includes('EPROTO')) {
            // If TLS fails, try plain TCP
            triedPlain = true;
            const plainSocket = new Socket();

            plainSocket.setTimeout(timeout);
            data = '';

            plainSocket.on('timeout', () => {
              logger.logError(debug, 'WHOIS query', 'Connection timeout');
              plainSocket.destroy();
              reject(new Error('Connection timeout'));
            });

            plainSocket.on('error', (error: Error) => {
              logger.logError(debug, 'WHOIS query', error);
              reject(error);
            });

            plainSocket.on('data', (chunk) => {
              data += chunk.toString();
            });

            plainSocket.on('end', () => {
              logger.logInfo(debug, 'WHOIS query', 'Connection closed');
              resolve(data);
            });

            plainSocket.connect(43, address, () => {
              logger.logInfo(
                debug,
                'WHOIS query',
                `Connected to ${server} (${address}) via plain TCP`
              );
              plainSocket.write(`${domain}\r\n`);
            });
          } else {
            logger.logError(debug, 'WHOIS query', error);
            reject(error);
          }
        });

        tlsSocket.on('data', (chunk) => {
          data += chunk.toString();
        });

        tlsSocket.on('end', () => {
          logger.logInfo(debug, 'WHOIS query', 'Connection closed');
          resolve(data);
        });

        tlsSocket.on('secureConnect', () => {
          logger.logInfo(debug, 'WHOIS query', `Connected to ${server} (${address}) via TLS`);
          tlsSocket.write(`${domain}\r\n`);
        });
      });
    } catch (error) {
      logger.logError(debug, 'WHOIS query', error);
      reject(error);
    }
  });
}

/**
 * Follows WHOIS server referrals to get the most complete data
 * @param domain The domain to query
 * @param initialServer The initial WHOIS server to query
 * @param maxReferrals Maximum number of referrals to follow
 * @param debug Whether to enable debug logging
 * @returns Promise resolving to the combined WHOIS response
 */
export async function followWhoisReferrals(
  domain: string,
  initialServer: string,
  maxReferrals = 3,
  debug = false
): Promise<string> {
  let response = await queryWhoisServer(domain, initialServer, 10000, debug);
  let currentServer = initialServer;
  let referralCount = 0;
  let finalResponse = response;

  if (debug) {
    console.log(`\n[DEBUG] Starting referral chain from ${initialServer}`);
  }

  // Check for WHOIS server redirection and follow if found
  while (referralCount < maxReferrals) {
    const nextServer = findReferralServer(response, currentServer);

    if (nextServer) {
      if (debug) {
        console.log(`[DEBUG] Found referral to ${nextServer}`);
      }
      // Follow the referral
      try {
        const nextResponse = await queryWhoisServer(domain, nextServer, 10000, debug);

        // If we get a meaningful response (not just a referral back)
        if (nextResponse && nextResponse.length > 100) {
          response = nextResponse;
          finalResponse += '\n\n# ' + nextServer + '\n\n' + nextResponse;
          currentServer = nextServer;
        }
      } catch (error) {
        // If the referral fails, just use what we have
        if (debug) {
          console.warn(
            `[DEBUG] Failed to follow WHOIS referral: ${
              error instanceof Error ? error.message : String(error)
            }`
          );
        }
        break;
      }
    } else {
      if (debug) {
        console.log('[DEBUG] No more referrals found');
      }
      break;
    }

    referralCount++;
  }

  if (debug) {
    console.log(`\n[DEBUG] Final combined response:`);
    console.log('='.repeat(80));
    console.log(finalResponse);
    console.log('='.repeat(80));
  }

  return finalResponse;
}
