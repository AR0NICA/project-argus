FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

ARG ARGUS_SOURCE_REVISION=unknown
ARG ARGUS_BUILD_CREATED=unknown
LABEL org.opencontainers.image.title="argus-gateway" \
      org.opencontainers.image.revision="$ARGUS_SOURCE_REVISION" \
      org.opencontainers.image.created="$ARGUS_BUILD_CREATED" \
      org.opencontainers.image.source="project-argus"

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends nginx libnginx-mod-http-modsecurity modsecurity-crs ca-certificates \
    && test -f /etc/modsecurity/crs/crs-setup.conf \
    && test -d /usr/share/modsecurity-crs/rules \
    && rm -rf /var/lib/apt/lists/*

COPY nginx.conf /etc/nginx/nginx.conf
COPY modsecurity.conf /etc/nginx/modsecurity/main.conf

EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
