# Multi-stage: build the static assets with Node, then serve them with
# a tiny nginx image — the final image doesn't carry node_modules or
# any build tooling, just the compiled dist/ output.

FROM node:22-slim AS build
WORKDIR /app
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./

# Vite bakes VITE_API_BASE into the built JS at build time (browser code
# can't read server-side env vars at runtime), so it has to be supplied
# as a build arg pointing at wherever the API is actually reachable —
# e.g. --build-arg VITE_API_BASE=https://api.yourdomain.com
ARG VITE_API_BASE=http://localhost:5000
ENV VITE_API_BASE=$VITE_API_BASE
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
