import type { IncomingMessage, ServerResponse } from 'http';
import { ProtectedResourceMetadataBuilder, BearerMethod } from '@auth0/auth0-api-js';
import type { HostedEnvConfig } from './env-config.js';
import { getAllScopes } from '../utils/scopes.js';

/**
 * Builds the OAuth 2.0 Protected Resource Metadata document (RFC 9728)
 * using @auth0/auth0-api-js ProtectedResourceMetadataBuilder.
 *
 * The MCP server advertises itself as a Protected Resource, pointing
 * MCP clients to Auth0 as the authorization server.
 */
function buildProtectedResourceMetadata(envConfig: HostedEnvConfig, serverBaseUrl: string) {
  const resource = envConfig.serverUrl || serverBaseUrl;

  return new ProtectedResourceMetadataBuilder(resource, [
    `https://${envConfig.auth0Domain}`,
  ])
    .withScopesSupported(getAllScopes())
    .withBearerMethodsSupported([BearerMethod.HEADER])
    .build()
    .toJSON();
}

/**
 * Handles GET /.well-known/oauth-protected-resource
 *
 * Returns the Protected Resource Metadata document (RFC 9728) that
 * MCP clients use to discover the authorization server for this
 * MCP server.
 */
export function handleProtectedResourceMetadata(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const serverBaseUrl =
    envConfig.serverUrl ||
    `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;

  const metadata = buildProtectedResourceMetadata(envConfig, serverBaseUrl);

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',
  });
  res.end(JSON.stringify(metadata, null, 2));
}
