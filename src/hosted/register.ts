import type { IncomingMessage, ServerResponse } from 'http';
import type { HostedEnvConfig } from './env-config.js';
import { log } from '../utils/logger.js';

/**
 * Handles POST /register — proxies to the authorization server's
 * Dynamic Client Registration endpoint (RFC 7591).
 *
 * Forwards the request body to Auth0 and returns Auth0's response
 * directly to the MCP client.
 */
export function handleRegister(
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
      const auth0RegisterUrl = `https://${envConfig.auth0Domain}/oidc/register`;

      log(`Proxying client registration to ${auth0RegisterUrl}`);

      const auth0Response = await fetch(auth0RegisterUrl, {
        method: 'POST',
        headers: {
          'Content-Type': req.headers['content-type'] || 'application/json',
        },
        body,
      });

      const responseBody = await auth0Response.text();

      res.writeHead(auth0Response.status, {
        'Content-Type': auth0Response.headers.get('content-type') || 'application/json',
      });
      res.end(responseBody);
    } catch (error) {
      log(`Register proxy error: ${error instanceof Error ? error.message : String(error)}`);
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Bad gateway', message: 'Failed to proxy registration request' }));
    }
  });
}
