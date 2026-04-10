FROM node:20-alpine
RUN apk add --no-cache nmap nikto perl john john-doc wget \
  && nikto -Version || true
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
