FROM alpine:3.10

RUN  apk add -U bash curl jq
RUN mkdir /app
WORKDIR /app
COPY update-vault.sh ./