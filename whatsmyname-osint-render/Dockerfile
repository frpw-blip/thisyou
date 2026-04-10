FROM node:20-alpine
RUN apk add --no-cache nmap nikto perl john john-doc wget \
  && wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/john/rockyou.txt || true
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
