FROM node:20-alpine

WORKDIR /app

# Install unzip for Assets.zip extraction
RUN apk add --no-cache unzip

# Create directories
RUN mkdir -p /app/data /app/assets

# Copy server and static assets
COPY server.js ./
COPY assets/*.js ./assets/
COPY assets/*.html ./assets/

EXPOSE 3000

CMD ["node", "server.js"]
