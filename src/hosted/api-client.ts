import { ApiClient } from '@auth0/auth0-api-js';
import type { HostedEnvConfig } from './env-config.js';

let apiClient: ApiClient | null = null;

/**
 * Returns a singleton ApiClient instance configured for token validation.
 *
 * The ApiClient validates user access tokens against Auth0's JWKS endpoint.
 * The audience is the MCP server's own URL — user tokens are issued for the
 * MCP server resource, not the Management API.
 */
export function getApiClient(envConfig: HostedEnvConfig): ApiClient {
  if (!apiClient) {
    apiClient = new ApiClient({
      domain: envConfig.auth0Domain,
      audience: envConfig.serverUrl,
    });
  }
  return apiClient;
}
