import type { IncomingMessage, ServerResponse } from 'http';
import type { HostedEnvConfig } from './env-config.js';

/**
 * Builds the OAuth 2.0 Authorization Server Metadata document (RFC 8414).
 * Points directly to Auth0's OAuth endpoints — our server does not proxy
 * any OAuth traffic, except for /register which we handle ourselves.
 */
function buildMetadata(envConfig: HostedEnvConfig, serverBaseUrl: string) {
  const issuer = `https://${envConfig.auth0Domain}/`;

  return {
    issuer,
    authorization_endpoint: `${serverBaseUrl}/authorize`,
    token_endpoint: `${serverBaseUrl}/token`,
    device_authorization_endpoint: `https://${envConfig.auth0Domain}/oauth/device/code`,
    userinfo_endpoint: `https://${envConfig.auth0Domain}/userinfo`,
    mfa_challenge_endpoint: `https://${envConfig.auth0Domain}/mfa/challenge`,
    jwks_uri: `https://${envConfig.auth0Domain}/.well-known/jwks.json`,
    registration_endpoint: `${serverBaseUrl}/register`,
    revocation_endpoint: `https://${envConfig.auth0Domain}/oauth/revoke`,
    scopes_supported: [
      'openid',
      'profile',
      'offline_access',
      'name',
      'given_name',
      'family_name',
      'nickname',
      'email',
      'email_verified',
      'picture',
      'created_at',
      'identities',
      'phone',
      'address',
    ],
    response_types_supported: [
      'code',
      'token',
      'id_token',
      'code token',
      'code id_token',
      'token id_token',
      'code token id_token',
    ],
    code_challenge_methods_supported: ['S256', 'plain'],
    response_modes_supported: ['query', 'fragment', 'form_post'],
    subject_types_supported: ['public'],
    token_endpoint_auth_methods_supported: [
      'client_secret_basic',
      'client_secret_post',
      'private_key_jwt',
    ],
    token_endpoint_auth_signing_alg_values_supported: ['RS256', 'RS384', 'PS256'],
    claims_supported: [
      'aud',
      'auth_time',
      'created_at',
      'email',
      'email_verified',
      'exp',
      'family_name',
      'given_name',
      'iat',
      'identities',
      'iss',
      'name',
      'nickname',
      'phone_number',
      'picture',
      'sub',
    ],
    request_uri_parameter_supported: false,
    request_parameter_supported: false,
    id_token_signing_alg_values_supported: ['HS256', 'RS256', 'PS256'],
    end_session_endpoint: `https://${envConfig.auth0Domain}/oidc/logout`,
    global_token_revocation_endpoint: `https://${envConfig.auth0Domain}/oauth/global-token-revocation/connection/{connectionName}`,
    global_token_revocation_endpoint_auth_methods_supported: [
      'global-token-revocation+jwt',
    ],
    dpop_signing_alg_values_supported: ['ES256'],
  };
}

/**
 * Handles GET /.well-known/oauth-authorization-server
 * Returns the OAuth metadata document that MCP clients use to discover
 * where to authenticate.
 */
export function handleOAuthMetadata(
  req: IncomingMessage,
  res: ServerResponse,
  envConfig: HostedEnvConfig
): void {
  if (req.method !== 'GET') {
    res.writeHead(405, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Method not allowed' }));
    return;
  }

  // Derive the server's base URL from SERVER_URL env or from the request
  const serverBaseUrl =
    envConfig.serverUrl ||
    `${req.headers['x-forwarded-proto'] || 'http'}://${req.headers.host}`;

  const metadata = buildMetadata(envConfig, serverBaseUrl);

  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',
  });
  res.end(JSON.stringify(metadata, null, 2));
}
