import type { IncomingMessage, ServerResponse } from 'http';
import { randomUUID } from 'crypto';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';

import { HANDLERS, TOOLS } from '../tools/index.js';
import { getAvailableTools } from '../utils/tools.js';
import { formatDomain } from '../utils/http-utility.js';
import { log, logInfo } from '../utils/logger.js';
import { packageVersion } from '../utils/package.js';
import type { HostedEnvConfig } from './env-config.js';

interface ActiveSession {
  server: Server;
  transport: StreamableHTTPServerTransport;
  token: string;
}

const sessions = new Map<string, ActiveSession>();

/**
 * Extracts Bearer token from the Authorization header.
 */
function extractBearerToken(req: IncomingMessage): string | null {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  return authHeader.slice(7);
}

/**
 * Creates a new MCP Server instance wired up with tool handlers.
 * Follows the same pattern as src/server.ts but uses the bearer token
 * from the HTTP request instead of keychain-based config.
 */
function createMcpServer(
  token: string,
  envConfig: HostedEnvConfig
): Server {
  const availableTools = getAvailableTools(TOOLS);
  const domain = formatDomain(envConfig.auth0Domain);

  const server = new Server(
    { name: 'auth0', version: packageVersion },
    { capabilities: { tools: {}, logging: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    log('Received list tools request');
    const sanitizedTools = availableTools.map(({ _meta, ...rest }) => rest);
    return { tools: sanitizedTools };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const toolName = request.params.name;
    log(`Received tool call: ${toolName}`);

    try {
      if (!HANDLERS[toolName]) {
        throw new Error(`Unknown tool: ${toolName}`);
      }

      const requestWithToken = {
        token,
        parameters: request.params.arguments || {},
      };

      log(`Executing handler for tool: ${toolName}`);
      const result = await HANDLERS[toolName](requestWithToken, { domain });
      log(`Handler execution completed for: ${toolName}`);

      return {
        content: result.content,
        isError: result.isError || false,
      };
    } catch (error) {
      log(
        `Error handling tool call: ${error instanceof Error ? error.message : String(error)}`
      );
      return {
        content: [
          {
            type: 'text',
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  });

  return server;
}

/**
 * Creates a new session: MCP Server + StreamableHTTPServerTransport.
 */
async function createSession(
  token: string,
  envConfig: HostedEnvConfig
): Promise<StreamableHTTPServerTransport> {
  const server = createMcpServer(token, envConfig);

  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: () => randomUUID(),
    onsessioninitialized: (sessionId: string) => {
      log(`Session initialized: ${sessionId}`);
      sessions.set(sessionId, { server, transport, token });

      const enabledToolsCount = getAvailableTools(TOOLS).length;
      const totalToolsCount = TOOLS.length;
      logInfo(
        `Auth0 MCP Server (hosted) session ${sessionId} started with ${enabledToolsCount}/${totalToolsCount} tools`
      );
    },
  });

  transport.onclose = () => {
    const sessionId = transport.sessionId;
    if (sessionId) {
      log(`Session closed: ${sessionId}`);
      sessions.delete(sessionId);
    }
  };

  await server.connect(transport);
  return transport;
}

/**
 * Handles all HTTP requests to /mcp (POST, GET, DELETE).
 * The StreamableHTTPServerTransport.handleRequest manages routing internally.
 */
export async function handleMcpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): Promise<void> {
  // Check for bearer token on all requests
  const token = extractBearerToken(req);
  if (!token) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Unauthorized', message: 'Bearer token required' }));
    return;
  }

  // Check for existing session
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId && sessions.has(sessionId)) {
    // Route to existing session's transport
    const session = sessions.get(sessionId)!;
    await session.transport.handleRequest(req, res);
    return;
  }

  // No session or unknown session — only accept POST (initialization)
  if (req.method !== 'POST') {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Bad Request', message: 'Invalid or missing session ID' }));
    return;
  }

  // New session — create server + transport, then handle the request
  const transport = await createSession(token, envConfig);
  await transport.handleRequest(req, res);
}
