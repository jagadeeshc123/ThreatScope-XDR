FROM node:20.19.4-alpine3.21 AS build

WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
ENV VITE_API_URL=""
RUN npm run build && ! find dist -type f -name '*.map' -print -quit | grep -q .

FROM nginx:1.28.0-alpine3.21 AS runtime

ARG BUILD_VERSION=1.0.0-rc2
ARG BUILD_REVISION=unknown
ARG BUILD_TIMESTAMP=unknown
LABEL org.opencontainers.image.title="ThreatScope XDR Edge" \
      org.opencontainers.image.description="Static frontend and TLS reverse proxy for ThreatScope XDR" \
      org.opencontainers.image.version=$BUILD_VERSION \
      org.opencontainers.image.revision=$BUILD_REVISION \
      org.opencontainers.image.created=$BUILD_TIMESTAMP \
      org.opencontainers.image.source="ThreatScope-XDR/main-platform/vulnscope" \
      org.opencontainers.image.licenses="Proprietary"

COPY --from=build --chown=101:101 /build/dist /usr/share/nginx/html
COPY --chown=101:101 deploy/nginx/nginx.conf.template /etc/threatscope/nginx.conf.template
COPY --chown=101:101 deploy/nginx/security-headers.conf /etc/threatscope/security-headers.conf
COPY --chown=101:101 deploy/nginx/proxy-common.conf /etc/threatscope/proxy-common.conf
COPY --chown=101:101 deploy/nginx/entrypoint.sh /usr/local/bin/threatscope-nginx-entrypoint
RUN chmod 0555 /usr/local/bin/threatscope-nginx-entrypoint \
    && find /usr/share/nginx/html -type f -exec chmod 0444 {} \; \
    && find /usr/share/nginx/html -type d -exec chmod 0555 {} \;

USER 101:101
EXPOSE 8080 8443
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=20s CMD ["wget", "--no-verbose", "--tries=1", "--spider", "--no-check-certificate", "https://127.0.0.1:8443/healthz"]
ENTRYPOINT ["/usr/local/bin/threatscope-nginx-entrypoint"]
