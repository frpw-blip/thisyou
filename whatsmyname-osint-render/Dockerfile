FROM node:20-alpine
RUN apk add --no-cache nmap nikto perl john john-doc wget python3 py3-pip git \
  && wget -q https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O /usr/share/john/rockyou.txt || true \
  && git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
  && find / -name "nikto.pl" 2>/dev/null | head -1 | xargs -I{} sh -c 'echo "#!/bin/sh\nexec perl {} \"\$@\"" > /usr/local/bin/nikto && chmod +x /usr/local/bin/nikto' || true
WORKDIR /app
COPY package.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["node", "server.js"]
