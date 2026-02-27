import { formatDomain } from '../utils/http-utility.js';
import type { Auth0Config } from '../utils/config.js';

export interface HostedEnvConfig {
  auth0Domain: string;
  auth0ClientId: string;
  auth0ClientSecret: string;
  auth0Audience: string;
  serverUrl: string;
  port: number;
}

/**
 * Loads and validates environment variables required for the hosted MCP server.
 * Throws if required variables are missing.
 */
export function loadEnvConfig(): HostedEnvConfig {
  const auth0Domain = process.env.AUTH0_DOMAIN;
  const auth0ClientId = process.env.AUTH0_CLIENT_ID;
  const auth0ClientSecret = process.env.AUTH0_CLIENT_SECRET;

  const missing: string[] = [];
  if (!auth0Domain) missing.push('AUTH0_DOMAIN');
  if (!auth0ClientId) missing.push('AUTH0_CLIENT_ID');
  if (!auth0ClientSecret) missing.push('AUTH0_CLIENT_SECRET');

  if (missing.length > 0) {
    throw new Error(
      `Missing required environment variables: ${missing.join(', ')}. ` +
        'Set these in your Railway dashboard or .env file.'
    );
  }

  const formattedDomain = formatDomain(auth0Domain!);
  const auth0Audience =
    process.env.AUTH0_AUDIENCE || `https://${formattedDomain}/api/v2/`;
  const serverUrl = process.env.SERVER_URL || '';
  const port = parseInt(process.env.PORT || '3000', 10);

  return {
    auth0Domain: formattedDomain,
    auth0ClientId: auth0ClientId!,
    auth0ClientSecret: auth0ClientSecret!,
    auth0Audience,
    serverUrl,
    port,
  };
}

/**
 * Creates an Auth0Config from a bearer token and the hosted environment config.
 * This replaces the keychain-based loadConfig() for hosted deployments.
 */
export function getHostedConfig(
  token: string,
  envConfig: HostedEnvConfig
): Auth0Config {
  return {
    token,
    domain: envConfig.auth0Domain,
    tenantName: envConfig.auth0Domain,
  };
}
