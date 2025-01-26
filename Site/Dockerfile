# syntax=docker/dockerfile:1
# This is a multi-stage file so we can restrict what the Docker build process itself has access to

ARG NODE_VERSION=22.13.0

# Copy Common
FROM node:${NODE_VERSION}-alpine AS build-common
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY Common/ /usr/src/app/Common/

# Copy Site
FROM node:${NODE_VERSION}-alpine AS build-site
WORKDIR /usr/src/app
COPY Site/ /usr/src/app/Site/
COPY Site/Keys/ /usr/src/app/Site/Keys/
WORKDIR /usr/src/app/Site

RUN --mount=type=bind,source=Site/package.json,target=package.json \
    --mount=type=bind,source=Site/package-lock.json,target=package-lock.json \
    --mount=type=cache,target=/root/.npm \
    npm ci --omit=dev

# Run the actual site - Copy from previous stages
FROM node:${NODE_VERSION}-alpine
WORKDIR /usr/src/app/Site

COPY --from=build-site /usr/src/app/Site/ /usr/src/app/Site/
COPY --from=build-common /usr/src/app/Common/ /usr/src/app/Common/

# Run the application as a non-root user.
USER node

# Expose the port that the application listens on.
EXPOSE 443
EXPOSE 80

# Run the application.
CMD ["npm", "start"]
