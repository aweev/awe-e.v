# Dockerfile

# 1. Base Image - For installing dependencies
FROM node:20-alpine AS base
WORKDIR /app
RUN npm install -g pnpm

# 2. Deps Stage - Install dependencies
FROM base AS deps
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile --prod=false

# 3. Builder Stage - Build the application
FROM base AS builder
COPY --from=deps /app/node_modules ./node_modules
COPY . .
# Generate Prisma Client
RUN pnpm prisma generate
# Build the Next.js application
RUN pnpm build

# 4. Runner Stage - The final, small production image
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production

# Copy necessary files from the builder stage
COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

# Start the server
EXPOSE 3000
CMD ["node", "server.js"]