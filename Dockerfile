FROM node:22-bookworm-slim AS base

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.json vitest.config.ts .oxlintrc.json ./
COPY apps/api-worker/package.json ./apps/api-worker/package.json
COPY packages/core-domain/package.json ./packages/core-domain/package.json
COPY packages/db/package.json ./packages/db/package.json
COPY packages/lti/package.json ./packages/lti/package.json
COPY packages/ui-components/package.json ./packages/ui-components/package.json
COPY packages/validation/package.json ./packages/validation/package.json

RUN pnpm install --frozen-lockfile

FROM node:22-bookworm-slim AS runtime

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV APP_ENV=production
ENV PLATFORM_DOMAIN=localhost
ENV PORT=8787
ENV STORAGE_BACKEND=s3

RUN corepack enable

WORKDIR /app

COPY --from=base /pnpm /pnpm
COPY --from=base /app/node_modules ./node_modules
COPY --from=base /app/apps ./apps
COPY --from=base /app/packages ./packages
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.json vitest.config.ts .oxlintrc.json ./
COPY apps ./apps
COPY packages ./packages
COPY scripts ./scripts
COPY docs ./docs

EXPOSE 8787

CMD ["pnpm", "exec", "tsx", "apps/api-worker/src/node-server.ts"]
