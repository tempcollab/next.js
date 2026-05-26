FROM node:20-alpine
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .

# Pre-place chain files for VULN-4 (arbitrary file read via source map endpoint)
RUN echo 'DEV_SECRET_KEY=sk-live-production-key-12345' > /tmp/dev_secret.txt

RUN printf '{\n  "version": 3,\n  "sources": ["/app/secret.js"],\n  "sourcesContent": ["DEV_SECRET_KEY=sk-live-production-key-12345"],\n  "mappings": "AAAA"\n}' > /tmp/secret_sourcemap.json

RUN printf '// chain\n//# sourceMappingURL=/tmp/secret_sourcemap.json\n' > /tmp/chain.js

RUN printf '// chain\n//# sourceMappingURL=/etc/passwd\n' > /tmp/chain_etc_passwd.js

ENV REACT_EDITOR=cat
EXPOSE 3000 9229
CMD ["sh", "-c", "NODE_OPTIONS='--inspect=0.0.0.0:9229' npx next dev --webpack --hostname 0.0.0.0 --port 3000"]
