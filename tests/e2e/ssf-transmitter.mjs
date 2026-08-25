/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';

const required = [
  'E2E_SSF_ISSUER', 'E2E_SSF_AUDIENCE', 'E2E_SSF_PUSH_SECRET', 'E2E_SSF_TRIGGER_SECRET',
  'E2E_SSF_OIDC_ISSUER', 'E2E_SSF_PUSH_URL', 'E2E_SSF_CERTIFICATE', 'E2E_SSF_KEY',
];
for (const name of required) {
  if (!process.env[name]) throw new Error(`${name} is required`);
}
const issuer = new URL(process.env.E2E_SSF_ISSUER);
const push = new URL(process.env.E2E_SSF_PUSH_URL);
if (issuer.protocol !== 'https:' || push.protocol !== 'https:' || issuer.search || issuer.hash) {
  throw new Error('SSF transmitter URLs must be bounded HTTPS URLs');
}
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const publicJwk = publicKey.export({ format: 'jwk' });
const signingKey = { ...publicJwk, alg: 'RS256', kid: 'e2e', use: 'sig' };
const json = body => Buffer.from(JSON.stringify(body));
const encode = body => json(body).toString('base64url');

function set() {
  const now = Math.floor(Date.now() / 1000);
  const header = encode({ alg: 'RS256', kid: 'e2e', typ: 'secevent+jwt' });
  const claims = encode({
    iss: issuer.toString().replace(/\/$/, ''),
    aud: process.env.E2E_SSF_AUDIENCE,
    iat: now,
    jti: randomUUID(),
    sub_id: { format: 'iss_sub', iss: process.env.E2E_SSF_OIDC_ISSUER, sub: 'e2e-ssf-subject' },
    events: {
      'https://schemas.openid.net/secevent/caep/event-type/session-revoked': { event_timestamp: now },
    },
  });
  const signingInput = `${header}.${claims}`;
  const signature = sign('RSA-SHA256', Buffer.from(signingInput), privateKey).toString('base64url');
  return `${signingInput}.${signature}`;
}

function respond(response, status, body = Buffer.alloc(0), contentType = 'text/plain') {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-length': body.length,
    'content-type': contentType,
  });
  response.end(body);
}

const server = createServer({
  cert: readFileSync(process.env.E2E_SSF_CERTIFICATE),
  key: readFileSync(process.env.E2E_SSF_KEY),
}, async (request, response) => {
  const path = new URL(request.url, issuer).pathname;
  const discoveryPath = `/.well-known/ssf-configuration${issuer.pathname.replace(/\/$/, '')}`;
  if (request.method === 'GET' && path === '/health') {
    respond(response, 204);
    return;
  }
  if (request.method === 'GET' && path === discoveryPath) {
    respond(response, 200, json({
      issuer: issuer.toString().replace(/\/$/, ''),
      jwks_uri: new URL('jwks', issuer.toString().replace(/\/$/, '') + '/').toString(),
      delivery_methods_supported: ['urn:ietf:rfc:8935'],
    }), 'application/json');
    return;
  }
  if (request.method === 'GET' && path === `${issuer.pathname.replace(/\/$/, '')}/jwks`) {
    respond(response, 200, json({ keys: [signingKey] }), 'application/json');
    return;
  }
  if (request.method === 'POST' && path === '/trigger'
      && request.headers.authorization === `Bearer ${process.env.E2E_SSF_TRIGGER_SECRET}`) {
    try {
      const delivered = await fetch(push, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${process.env.E2E_SSF_PUSH_SECRET}`,
          'Content-Type': 'application/secevent+jwt',
        },
        body: set(),
        redirect: 'manual',
        signal: AbortSignal.timeout(20_000),
      });
      respond(response, delivered.status === 202 ? 204 : 502);
    } catch {
      // The caller needs only a bounded success/failure signal; endpoint and
      // transport detail could disclose the randomly generated tunnel origin.
      respond(response, 502);
    }
    return;
  }
  respond(response, 404);
});
server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.listen(4443, '0.0.0.0');
