#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Combined Node test server: REST HTTPS + gRPC-TLS in one process.
// Capture path: apidump-ebpf (libssl / static BoringSSL uprobes on node).

'use strict';

const fs = require('fs');
const https = require('https');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const TLS_DIR = process.env.TLS_DIR || '/tls';
const BIND = process.env.BIND_HOST || '0.0.0.0';
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 8443);
const GRPC_PORT = Number(process.env.GRPC_PORT || 8446);

const certPath = path.join(TLS_DIR, 'grpc-cert.pem');
const keyPath = path.join(TLS_DIR, 'grpc-key.pem');
const protoPath = path.join(__dirname, 'proto', 'greeter.proto');

function loadTls() {
  if (!fs.existsSync(certPath) || !fs.existsSync(keyPath)) {
    throw new Error(`missing TLS files under ${TLS_DIR} (need grpc-cert.pem, grpc-key.pem)`);
  }
  return {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  };
}

function startHttps(tls) {
  const server = https.createServer(tls, (req, res) => {
    const pathname = (req.url || '/').split('?')[0];
    if (req.method !== 'GET' || (pathname !== '/phase5b2' && pathname !== '/')) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found\n');
      return;
    }
    const qs = req.url && req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(`hello-from-node-combined-server phase=5b2${qs}\n`);
  });
  server.listen(HTTPS_PORT, BIND, () => {
    console.error(`HTTPS listening on https://${BIND}:${HTTPS_PORT}/phase5b2`);
  });
  return server;
}

function startGrpc(tls) {
  const def = protoLoader.loadSync(protoPath, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const greeter = grpc.loadPackageDefinition(def).phase5c2;

  const impl = {
    sayHello: (call, callback) => {
      const name = call.request.name || 'world';
      callback(null, { message: `hi ${name} from-node-combined-server` });
    },
  };

  const server = new grpc.Server();
  server.addService(greeter.Greeter.service, impl);

  const creds = grpc.ServerCredentials.createSsl(null, [
    { cert_chain: tls.cert, private_key: tls.key },
  ], false);

  server.bindAsync(`${BIND}:${GRPC_PORT}`, creds, (err, port) => {
    if (err) throw err;
    server.start();
    console.error(`gRPC listening on https://${BIND}:${port} (h2) phase5c2.Greeter/SayHello`);
  });
  return server;
}

const tls = loadTls();
startHttps(tls);
startGrpc(tls);
