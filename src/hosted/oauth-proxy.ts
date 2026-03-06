import type { IncomingMessage, ServerResponse } from 'http';
import { log } from '../utils/logger.js';
import type { HostedEnvConfig } from './env-config.js';

/**
 * Returns the Management API audience with a wildcard tenant prefix.
 *
 * For domain "tenant.example.auth0.com", returns "https://*.example.auth0.com/api/v2/"
 * This allows the token to work across tenant subdomains.
 */
function getManagementApiAudience(envConfig: HostedEnvConfig): string {
  const domain = envConfig.auth0Domain;
  // Strip the first subdomain (tenant name) and replace with wildcard
  const parts = domain.split('.');
  const wildcardDomain = parts.length > 2 ? `*.${parts.slice(1).join('.')}` : `*.${domain}`;
  return `https://${wildcardDomain}/api/v2/`;
}

/**
 * Handles GET /authorize — proxies to Auth0's /authorize endpoint.
 *
 * Swaps the `resource` query parameter from the MCP server URL to the
 * Auth0 Management API audience, so the resulting token is scoped for
 * the Management API. All other parameters are passed through unchanged.
 */
export function handleAuthorizeProxy(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  const incomingUrl = new URL(req.url || '/', `http://${req.headers.host}`);
  const params = incomingUrl.searchParams;

  // Swap resource to Management API audience
  const originalResource = params.get('resource');
  const managementAudience = getManagementApiAudience(envConfig);
  params.set('resource', managementAudience);

  // Also set audience if not already present (some Auth0 flows use audience instead of resource)
  if (!params.has('audience')) {
    params.set('audience', managementAudience);
  }

  log(
    `Authorize proxy: resource ${originalResource} -> ${managementAudience}`
  );

  // Redirect to Auth0's /authorize
  const auth0AuthorizeUrl = `https://${envConfig.auth0Domain}/authorize?${params.toString()}`;

  res.writeHead(302, { Location: auth0AuthorizeUrl });
  res.end();
}

/**
 * Handles POST /oauth/token — proxies to Auth0's /oauth/token endpoint.
 *
 * Reads the form-encoded body, swaps the `resource` parameter to the
 * Management API audience, and forwards the request to Auth0. Returns
 * Auth0's response directly to the client.
 */
export function handleTokenProxy(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  if (req.method !== 'POST') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  let body = '';
  req.on('data', (chunk: Buffer) => {
    body += chunk.toString();
  });

  req.on('end', async () => {
    try {
      const managementAudience = getManagementApiAudience(envConfig);

      // Parse the body — could be form-encoded or JSON
      let forwardBody: string;
      const contentType = req.headers['content-type'] || '';

      if (contentType.includes('application/json')) {
        const parsed = JSON.parse(body);
        const originalResource = parsed.resource;
        parsed.resource = managementAudience;
        if (!parsed.audience) {
          parsed.audience = managementAudience;
        }
        log(`Token proxy: resource ${originalResource} -> ${managementAudience}`);
        forwardBody = JSON.stringify(parsed);
      } else {
        // Form-encoded
        const params = new URLSearchParams(body);
        const originalResource = params.get('resource');
        params.set('resource', managementAudience);
        if (!params.has('audience')) {
          params.set('audience', managementAudience);
        }
        log(`Token proxy: resource ${originalResource} -> ${managementAudience}`);
        forwardBody = params.toString();
      }

      // Forward to Auth0, passing through relevant headers
      const auth0TokenUrl = `https://${envConfig.auth0Domain}/oauth/token`;
      const forwardHeaders: Record<string, string> = {
        'Content-Type': contentType || 'application/x-www-form-urlencoded',
      };
      // Pass through Authorization header (client_secret_basic, DPoP, etc.)
      if (req.headers.authorization) {
        forwardHeaders['Authorization'] = req.headers.authorization;
      }
      // Pass through DPoP proof if present
      if (req.headers.dpop) {
        forwardHeaders['DPoP'] = req.headers.dpop as string;
      }

      const auth0Response = await fetch(auth0TokenUrl, {
        method: 'POST',
        headers: forwardHeaders,
        body: forwardBody,
      });

      const responseBody = await auth0Response.text();

      // Pass through Auth0's response
      res.writeHead(auth0Response.status, {
        'Content-Type': auth0Response.headers.get('content-type') || 'application/json',
      });
      res.end(responseBody);
    } catch (error) {
      log(`Token proxy error: ${error instanceof Error ? error.message : String(error)}`);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad gateway', message: 'Failed to proxy token request' }));
    }
  });
}
