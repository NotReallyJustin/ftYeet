# syntax=docker/dockerfile:1
# This is a multi-stage file so we can restrict what the Docker build process itself has access to

ARG NODE_VERSION=22.13.0

# Copy Common
FROM node:${NODE_VERSION}-alpine AS build-common
ENV NODE_ENV=production
WORKDIR /usr/src/app
COPY Common/ /usr/src/app/Common/

# Copy one file in Crypto
FROM node:${NODE_VERSION}-alpine AS build-Crypto
WORKDIR /usr/src/Crypto
COPY Crypto/cryptoFunc.js /usr/src/Crypto/cryptoFunc.js

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
COPY --from=build-Crypto /usr/src/Crypto/ /usr/src/app/Site/Crypto/

# Make a directory that node can write to
RUN mkdir /usr/src/app/Site/files

# x permission for dirs == you can $cd into it
# +x to a dir doesn't give +x to files inside it, so we good. By default, when a file is created, it doesn't have execute perms for owner.
# We will address the issue of execution later by changing file owner to root, changing group to $FWGROUPNAME, and restricting +x perms
RUN chmod 777 /usr/src/app/Site/files           

# In the future, add apparmor for security hardening. That can happen later tho

# Run the application as a non-root user.
USER node

# Expose the port that the application listens on.
EXPOSE 443
EXPOSE 80

# Run the application.
CMD ["npm", "start"]