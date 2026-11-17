FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json tsconfig.json ./
RUN npm install

COPY mcp-server ./mcp-server
COPY core-engine ./core-engine
COPY demo-fixtures ./demo-fixtures

RUN npm run build

CMD ["npm", "run", "mcp:start"]
