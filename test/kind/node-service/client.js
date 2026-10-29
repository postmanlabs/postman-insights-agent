#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
//
// Combined client: one HTTPS GET + N gRPC SayHello calls (verified TLS).

'use strict';

const fs = require('fs');
const https = require('https');
const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const TLS_DIR = process.env.TLS_DIR || '/tls';
const HOST = process.env.BIND_HOST || '127.0.0.1';
const HTTPS_PORT = Number(process.env.HTTPS_PORT || 8443);
const GRPC_PORT = Number(process.env.GRPC_PORT || 8446);
const COUNT = Number(process.argv[2] || 3);

const trustPath = path.join(TLS_DIR, 'hello-https-trust.pem');
const protoPath = path.join(__dirname, 'proto', 'greeter.proto');

function httpsGet() {
  return new Promise((resolve, reject) => {
    const ca = fs.readFileSync(trustPath);
    const req = https.get(
      {
        hostname: HOST,
        port: HTTPS_PORT,
        path: '/phase5b2',
        ca,
        servername: 'localhost',
      },
      (res) => {
        let body = '';
        res.on('data', (c) => { body += c; });
        res.on('end', () => {
          console.error(`https GET /phase5b2 → status=${res.statusCode} body=${body.trim()}`);
          resolve();
        });
      },
    );
    req.on('error', reject);
  });
}

async function grpcCalls() {
  const ca = fs.readFileSync(trustPath);
  const def = protoLoader.loadSync(protoPath, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const greeter = grpc.loadPackageDefinition(def).phase5c2;
  const client = new greeter.Greeter(
    `${HOST}:${GRPC_PORT}`,
    grpc.credentials.createSsl(ca, null, null, { checkServerIdentity: () => undefined }),
  );

  for (let i = 0; i < COUNT; i++) {
    await new Promise((resolve, reject) => {
      client.sayHello({ name: `node-combined-${i}` }, (err, reply) => {
        if (err) return reject(err);
        console.error(`grpc SayHello → ${reply.message}`);
        resolve();
      });
    });
  }
  client.close();
}

async function main() {
  if (!fs.existsSync(trustPath)) {
    throw new Error(`missing trust PEM: ${trustPath}`);
  }
  await httpsGet();
  await grpcCalls();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
