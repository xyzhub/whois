/**
 * Utility functions for logging and error handling
 */

/**
 * Logs an error message in debug mode
 * @param debug Whether debug mode is enabled
 * @param section The section where the error occurred
 * @param error The error object or message
 */
export function logError(debug: boolean, section: string, error: unknown): void {
  if (debug) {
    console.error(`[DEBUG] Error fetching ${section}:`, error);
  }
}

/**
 * Logs a warning message in debug mode
 * @param debug Whether debug mode is enabled
 * @param section The section where the warning occurred
 * @param message The warning message
 */
export function logWarning(debug: boolean, section: string, message: string): void {
  if (debug) {
    console.warn(`[DEBUG] Warning in ${section}:`, message);
  }
}

/**
 * Logs an informational message in debug mode
 * @param debug Whether debug mode is enabled
 * @param section The section where the info occurred
 * @param message The informational message
 */
export function logInfo(debug: boolean, section: string, message: string): void {
  if (debug) {
    console.log(`[DEBUG] ${section}:`, message);
  }
}

// Export all logging functions
export default {
  logError,
  logWarning,
  logInfo,
};
