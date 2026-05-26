FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
WORKDIR /app
COPY package.json .
RUN npm install
COPY . .
RUN npx next build
EXPOSE 3000
CMD ["npx", "next", "start", "-p", "3000"]
