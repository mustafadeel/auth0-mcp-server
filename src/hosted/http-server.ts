import http from 'http';
import { loadEnvConfig } from './env-config.js';
import { handleOAuthMetadata } from './oauth-metadata.js';
import { handleRegister } from './register.js';
import { handleAuthorize, handleToken } from './oauth-proxy.js';
import { handleMcpRequest } from './mcp-handler.js';
import { logInfo, logError } from '../utils/logger.js';
import { packageVersion } from '../utils/package.js';

const envConfig = loadEnvConfig();

/**
 * Sets CORS headers on the response.
 * Allows cross-origin requests from MCP clients.
 */
function setCorsHeaders(res: http.ServerResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, Mcp-Session-Id, Accept, Mcp-Protocol-Version'
  );
  res.setHeader(
    'Access-Control-Expose-Headers',
    'Mcp-Session-Id'
  );
}

/**
 * Main request router.
 */
function handleRequest(
  req: http.IncomingMessage,
  res: http.ServerResponse
): void {
  setCorsHeaders(res);

  // Handle preflight
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const url = new URL(req.url || '/', `http://${req.headers.host}`);
  const pathname = url.pathname;

  // Route: OAuth metadata discovery
  if (pathname === '/.well-known/oauth-authorization-server') {
    handleOAuthMetadata(req, res, envConfig);
    return;
  }

  // Route: Dynamic client registration (RFC 7591)
  if (pathname === '/register') {
    handleRegister(req, res, envConfig);
    return;
  }

  // Route: OAuth authorize proxy (injects audience + scopes, redirects to Auth0)
  if (pathname === '/authorize') {
    handleAuthorize(req, res, envConfig);
    return;
  }

  // Route: OAuth token proxy (forwards to Auth0 /oauth/token)
  if (pathname === '/token') {
    handleToken(req, res, envConfig);
    return;
  }

  // Route: MCP endpoint (POST, GET, DELETE all handled by the transport)
  if (pathname === '/mcp') {
    handleMcpRequest(req, res, envConfig).catch((error) => {
      logError('Error handling MCP request:', error);
      if (!res.headersSent) {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal server error' }));
      }
    });
    return;
  }

  // Health check
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(
      JSON.stringify({
        status: 'ok',
        version: packageVersion,
        auth0Domain: envConfig.auth0Domain,
      })
    );
    return;
  }

  // 404 for everything else
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

const server = http.createServer(handleRequest);

server.listen(envConfig.port, () => {
  logInfo(`Auth0 MCP Server (hosted) v${packageVersion}`);
  logInfo(`Listening on port ${envConfig.port}`);
  logInfo(`MCP endpoint: /mcp`);
  logInfo(`OAuth metadata: /.well-known/oauth-authorization-server`);
  logInfo(`Auth0 domain: ${envConfig.auth0Domain}`);
  if (envConfig.serverUrl) {
    logInfo(`Public URL: ${envConfig.serverUrl}`);
  }
});
