FROM node:22-bookworm-slim

WORKDIR /app

COPY package.json package-lock.json* ./
# npm ci = reproducible install from the lockfile (fails if out of sync).
RUN npm ci

COPY . .

EXPOSE 5173

CMD ["npm", "run", "dev"]
