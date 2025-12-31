# ⚛️ Frontend Dockerfile
# Multi-stage build for development and production

# ==========================================
# 🏗️ Builder Stage
# ==========================================
FROM node:18-alpine as builder

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

# ==========================================
# 🚀 Production Stage
# ==========================================
FROM nginx:alpine as production

# Copy build artifacts
COPY --from=builder /app/build /usr/share/nginx/html

# Copy nginx config (if custom config exists)
# COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]

# ==========================================
# 🛠️ Development Stage
# ==========================================
FROM node:18-alpine as development

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 3000

CMD ["npm", "run", "dev"]
