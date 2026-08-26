/*
 * Copyright (C) 2026 Julian Pawlowski
 * All rights reserved. BSD-2-Clause, see LICENSE at the repository root.
 */

import { createServer } from 'node:http';

const upstream = new URL(process.env.EMULATE_UPSTREAM);
const provider = process.env.EMULATE_PROVIDER;
if (provider !== 'apple' || upstream.protocol !== 'http:') throw new Error('unsafe emulator adapter configuration');

createServer(async (request, response) => {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 1024 * 1024) {
      response.writeHead(413).end();
      return;
    }
    chunks.push(chunk);
  }
  const headers = { ...request.headers };
  delete headers.host;
  delete headers['content-length'];
  const requested = new URL(request.url, 'http://adapter.invalid');
  const target = new URL(`${requested.pathname}${requested.search}`, upstream);
  let upstreamResponse;
  try {
    upstreamResponse = await fetch(target, {
      method: request.method,
      headers,
      body: chunks.length ? Buffer.concat(chunks) : undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(20_000),
    });
  } catch {
    response.writeHead(502).end();
    return;
  }
  const outputHeaders = Object.fromEntries(upstreamResponse.headers);
  delete outputHeaders['content-length'];
  delete outputHeaders['content-encoding'];
  delete outputHeaders['transfer-encoding'];
  if (target.pathname === '/.well-known/openid-configuration') {
    const discovery = await upstreamResponse.json();
    discovery.code_challenge_methods_supported = ['S256'];
    discovery.response_modes_supported = Array.from(new Set([
      ...(discovery.response_modes_supported || []), 'form_post',
    ]));
    const body = Buffer.from(JSON.stringify(discovery));
    response.writeHead(upstreamResponse.status, { ...outputHeaders, 'content-length': body.length });
    response.end(body);
    return;
  }
  const body = Buffer.from(await upstreamResponse.arrayBuffer());
  response.writeHead(upstreamResponse.status, { ...outputHeaders, 'content-length': body.length });
  response.end(body);
}).listen(4100, '0.0.0.0');
