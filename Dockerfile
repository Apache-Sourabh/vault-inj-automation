FROM alpine:3.10

RUN  apk add -U --no-cache bash curl jq apache2-utils
RUN mkdir /app
WORKDIR /app
COPY update-vault.sh ./