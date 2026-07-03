FROM node:24-bookworm-slim AS deps

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH

RUN corepack enable

WORKDIR /app

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY tsconfig.json vitest.config.ts .oxlintrc.json rolldown.node-runtime.config.mjs ./
COPY apps/api-worker/package.json ./apps/api-worker/package.json
COPY packages/core-domain/package.json ./packages/core-domain/package.json
COPY packages/db/package.json ./packages/db/package.json
COPY packages/ui-components/package.json ./packages/ui-components/package.json
COPY packages/validation/package.json ./packages/validation/package.json

RUN pnpm install --frozen-lockfile

FROM deps AS deploy

COPY apps ./apps
COPY packages ./packages

RUN pnpm build:node-runtime:prod
RUN pnpm --filter @credtrail/api-worker deploy --prod --legacy /prod
RUN mkdir -p /prod/dist/node-runtime \
  && cp -R apps/api-worker/dist/node-runtime/. /prod/dist/node-runtime/

FROM node:24-bookworm-slim AS runtime

ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
ENV APP_ENV=production
ENV PLATFORM_DOMAIN=localhost
ENV PORT=8787
ENV STORAGE_BACKEND=s3

RUN corepack enable

WORKDIR /app

COPY --from=deploy /prod ./

EXPOSE 8787

CMD ["node", "dist/node-runtime/node-server-runtime.js"]
