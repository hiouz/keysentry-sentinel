FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY dist ./dist
COPY server ./server
RUN mkdir -p /data && chown -R node:node /app /data
USER node
ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=4174
ENV KEYSENTRY_DATA=/data/state.json
EXPOSE 4174
CMD ["node", "server/index.mjs"]
