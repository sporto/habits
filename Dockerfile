FROM ghcr.io/gleam-lang/gleam:v1.5.1-erlang-alpine
WORKDIR /source
RUN apk add just
RUN apk add --update nodejs npm
COPY src src
COPY gleam.toml .
COPY index.html .
COPY Justfile .
COPY manifest.toml .
COPY package.json .
COPY package-lock.json .
COPY vite.config.ts .
RUN npm install
RUN just build
