# Node combined HTTPS + gRPC test server for kind (libssl eBPF capture path).
#
#   docker build -f test/e2e/apps/node-service/Dockerfile -t pia-node-service:test .
#   kind load docker-image pia-node-service:test --name pia-https-test

FROM node:20-bookworm-slim

WORKDIR /app
COPY test/e2e/apps/node-service/package.json ./
RUN npm install --omit=dev

COPY test/e2e/apps/node-service/server.js test/e2e/apps/node-service/client.js ./
COPY test/e2e/apps/node-service/proto ./proto

RUN chown -R node:node /app
USER node

ENV TLS_DIR=/tls \
    BIND_HOST=0.0.0.0 \
    HTTPS_PORT=8443 \
    GRPC_PORT=8446

EXPOSE 8443 8446
CMD ["node", "server.js"]
