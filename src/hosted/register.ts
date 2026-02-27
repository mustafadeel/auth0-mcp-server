import type { IncomingMessage, ServerResponse } from 'http';
import type { HostedEnvConfig } from './env-config.js';
import { log } from '../utils/logger.js';

/**
 * Handles POST /register — OAuth 2.0 Dynamic Client Registration (RFC 7591).
 *
 * This is a simplified implementation for the POC. Instead of creating a new
 * Auth0 application per registration request, it returns the pre-configured
 * AUTH0_CLIENT_ID from environment variables. This means all MCP clients
 * share the same SPA application in Auth0.
 *
 * The response follows the RFC 7591 format so MCP clients can consume it
 * as a standard dynamic registration response.
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

  // Read the request body (RFC 7591 sends client metadata as JSON)
  let body = '';
  req.on('data', (chunk: Buffer) => {
    body += chunk.toString();
  });

  req.on('end', () => {
    let clientName = 'MCP Client';
    let redirectUris: string[] = [];

    try {
      if (body) {
        const registration = JSON.parse(body);
        clientName = registration.client_name || clientName;
        redirectUris = registration.redirect_uris || redirectUris;
      }
    } catch {
      // Ignore parse errors — use defaults
    }

    log(`Client registration request from: ${clientName}`);

    // Return the pre-configured client_id in RFC 7591 response format
    const response = {
      client_id: envConfig.auth0ClientId,
      client_name: clientName,
      redirect_uris: redirectUris,
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      application_type: 'web',
    };

    res.writeHead(201, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(response, null, 2));
  });
}
