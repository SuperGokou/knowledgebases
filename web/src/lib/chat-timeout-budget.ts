/**
 * One bounded end-to-end budget for the two-stage chat pipeline.
 *
 * The server cancels model work first. The BFF then has ten seconds to carry
 * the stable 504 response back to the browser, which retains a final ten
 * seconds for transport and rendering. Do not independently raise one layer:
 * preserving this strict ordering is what prevents orphaned model work.
 */
export const CHAT_SERVER_TIMEOUT_MS = 95_000;
export const CHAT_BFF_TIMEOUT_MS = 105_000;
export const CHAT_BROWSER_TIMEOUT_MS = 115_000;

const CHAT_QUERY_PATHS = new Set([
  "/api/v1/chat/query",
  "/api/v1/public/chat/query",
]);

export function isChatQueryPath(pathname: string): boolean {
  return CHAT_QUERY_PATHS.has(pathname);
}
