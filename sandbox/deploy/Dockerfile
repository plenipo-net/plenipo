# The whole sandbox in one image: the Plenipo library built from this repository, the five services and the
# hosted MCP gateway. Used by docker-compose.yml here and by fly.toml.
# Build from the repository root:
#   docker build -f sandbox/deploy/Dockerfile -t plenipo-sandbox .
FROM node:22.22-bookworm-slim AS build
WORKDIR /app
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --no-audit --no-fund
COPY src ./src
RUN npm run build
COPY sandbox/package.json sandbox/package-lock.json ./sandbox/
RUN cd sandbox && npm ci --no-audit --no-fund
COPY sandbox ./sandbox

FROM node:22.22-bookworm-slim
ENV NODE_ENV=production \
    SANDBOX_HOST=0.0.0.0
WORKDIR /app
COPY --from=build --chown=node:node /app /app
USER node
WORKDIR /app/sandbox
EXPOSE 4400 4401 4402 4403 4404 4405 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s \
  CMD node -e "fetch('http://127.0.0.1:4403/api/info').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node_modules/.bin/tsx", "src/main.ts"]
