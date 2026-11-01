FROM nineseconds/mtg:2 AS mtg
FROM node:20-alpine
ARG TARGETARCH
RUN apk add --no-cache wget unzip ca-certificates certbot
RUN set -e; case "$TARGETARCH" in arm64) XA=arm64-v8a; HA=arm64;; *) XA=64; HA=amd64;; esac; \
 wget -qO /tmp/x.zip https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-$XA.zip; \
 unzip -q /tmp/x.zip xray -d /usr/local/bin; chmod +x /usr/local/bin/xray; rm /tmp/x.zip; \
 wget -qO /usr/local/bin/hysteria https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-$HA; chmod +x /usr/local/bin/hysteria
COPY --from=mtg /mtg /usr/local/bin/mtg
WORKDIR /app
COPY . .
RUN npm i --omit=dev
ENV DATA_DIR=/data
VOLUME /data
CMD ["node","server.js"]
