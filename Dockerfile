FROM node:22-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev
COPY lib ./lib
COPY start.js ./
COPY public ./public
ENV DATA_DIR=/app/data
VOLUME /app/data
EXPOSE 3000
CMD ["npm", "start"]
