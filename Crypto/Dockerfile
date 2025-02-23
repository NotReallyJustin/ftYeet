# This is a multi-stage file so we can restrict what the Docker build process itself has access to
ARG NODE_VERSION=22.13.0

# Copy Common
FROM node:${NODE_VERSION}-alpine AS build-common
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY Common/ /usr/src/app/Common/

# Copy Crypto
FROM node:${NODE_VERSION}-alpine AS build-crypto
WORKDIR /usr/src/app
COPY Crypto/ /usr/src/app/Crypto/
# COPY Crypto/Keys/ /usr/src/app/Crypto/Keys/
WORKDIR /usr/src/app/Crypto

RUN --mount=type=bind,source=Site/package.json,target=package.json \
    --mount=type=bind,source=Site/package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev

# Run the actual site - Copy from previous stages
FROM node:${NODE_VERSION}-alpine
WORKDIR /usr/src/app/Crypto

COPY --from=build-site /usr/src/app/Crypto/ /usr/src/app/Crypto/
COPY --from=build-common /usr/src/app/Crypto/ /usr/src/app/Crypto/

# Run the application as a non-root user.
USER node

# Run the application.
CMD ["npm", "start"]