# Builds the supervisor image (the CPU release workflow pushes it; metal/build-image.mjs folds it into the measured guest).
# Keep deps minimal — this image is measured and published; smaller TCB = easier audit.
# Base pinned by DIGEST (not just the mutable 20-slim tag) so the measured TCB is
# reproducible build-to-build. Re-pin deliberately on a base bump:
#   curl -s "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/node:pull" ... (Docker-Content-Digest of node:20-slim)
FROM node:20-slim@sha256:2cf067cfed83d5ea958367df9f966191a942351a2df77d6f0193e162b5febfc0
# openssl mints the in-enclave TLS-bridge key + self-signed cert at boot (initTlsBridge).
# (The SSH owner-access channel was removed in ad2f4f0e — openssh-server/-client are gone.)
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# npm ci (not install): installs the EXACT locked tree; requires an in-sync
# package-lock.json (no `*` glob — a missing lockfile must FAIL, not silently float).
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY supervisor.js ./
COPY sdk/bootstrap/package.mjs ./sdk/bootstrap/
COPY windows/node/verification-checkpoints.mjs ./windows/node/
COPY windows/node/host-admission.bundle.mjs ./windows/node/
# wallet sessions as owner credentials (shared with the Windows node, which ships it through deploy-files.mjs)
COPY windows/node/session-api-auth.mjs ./windows/node/
# dedicated-IP egress: the enclave-side SOCKS front + its SSRF classifier
# (net-guard.mjs is also symlinked into relay/ and shipped to the relay box).
COPY egress.js ./
COPY addressbook.js ./
COPY net-guard.mjs ./
# If you add the spawn implementation in its own files, COPY them here too.
ENV PORT=8080
EXPOSE 8080
CMD ["node", "supervisor.js"]
