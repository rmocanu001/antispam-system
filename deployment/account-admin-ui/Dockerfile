# ---- build ----
FROM node:22-alpine AS builder

WORKDIR /app
COPY package.json ./
RUN npm install --legacy-peer-deps

COPY angular.json tsconfig.json ./
COPY src/ src/

RUN npx ng build --configuration production

# ---- serve ----
FROM nginx:1.27-alpine

COPY --from=builder /app/dist/account-admin-ui/browser /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Remove default nginx.conf (port 80 catch-all)
RUN rm -f /etc/nginx/conf.d/default.conf.orig 2>/dev/null || true

EXPOSE 80 443
