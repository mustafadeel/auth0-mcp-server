import type { IncomingMessage, ServerResponse } from 'http';
import type { HostedEnvConfig } from './env-config.js';
import { getAllScopes } from '../utils/scopes.js';
import { log } from '../utils/logger.js';

/**
 * The Management API scopes required by the MCP tools.
 */
const REQUIRED_SCOPES = getAllScopes();

/**
 * Handles GET /authorize — proxies to Auth0's /authorize endpoint.
 *
 * Per MCP spec 2025-06-18, the client sends a `resource` parameter (RFC 8707)
 * identifying the MCP server it wants a token for. Auth0 uses the `resource`
 * parameter (with Resource Parameter Compatibility Profile enabled) to scope
 * the token to the correct API.
 *
 * This proxy also injects the required Management API scopes.
 */
export function handleAuthorize(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  const incomingUrl = new URL(req.url || '/', `http://${req.headers.host}`);
  const params = incomingUrl.searchParams;

  // The MCP client sends `resource` = MCP server URL (per RFC 8707),
  // but Auth0 needs `audience` = Management API identifier to issue
  // a token with the right API permissions. Always override audience.
  params.set('audience', envConfig.auth0Audience);

  // Remove the `resource` param so Auth0 doesn't try to use it as the audience
  params.delete('resource');

  // Inject/merge scopes — add Management API scopes to whatever the client requested
  const clientScopes = params.get('scope') || '';
  const clientScopeList = clientScopes.split(' ').filter(Boolean);
  const mergedScopes = [...new Set([...clientScopeList, ...REQUIRED_SCOPES, 'openid', 'offline_access'])];
  params.set('scope', mergedScopes.join(' '));

  const auth0AuthorizeUrl = `https://${envConfig.auth0Domain}/authorize?${params.toString()}`;

  log(`Redirecting to Auth0 /authorize with audience=${params.get('audience')} and ${mergedScopes.length} scopes`);

  res.writeHead(302, { Location: auth0AuthorizeUrl });
  res.end();
}

/**
 * Handles POST /token — proxies to Auth0's /oauth/token endpoint.
 *
 * Per MCP spec 2025-06-18, the client includes the `resource` parameter
 * in token requests too. We forward the body as-is to Auth0.
 */
export function handleToken(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Collect the request body
  const chunks: Buffer[] = [];
  req.on('data', (chunk: Buffer) => {
    chunks.push(chunk);
  });

  req.on('end', async () => {
    const body = Buffer.concat(chunks);
    const contentType = req.headers['content-type'] || 'application/x-www-form-urlencoded';

    log('Proxying token request to Auth0');

    try {
      const auth0TokenUrl = `https://${envConfig.auth0Domain}/oauth/token`;
      const auth0Res = await fetch(auth0TokenUrl, {
        method: 'POST',
        headers: {
          'Content-Type': contentType,
        },
        body,
      });

      const auth0Body = await auth0Res.text();

      // Forward Auth0's response headers and body
      res.writeHead(auth0Res.status, {
        'Content-Type': auth0Res.headers.get('content-type') || 'application/json',
      });
      res.end(auth0Body);
    } catch (error) {
      log('Error proxying token request:', error);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad gateway', message: 'Failed to reach Auth0 token endpoint' }));
    }
  });
}
