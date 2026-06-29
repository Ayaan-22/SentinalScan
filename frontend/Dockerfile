# Build stage
FROM node:20-alpine as build-stage

WORKDIR /app

ARG VITE_API_URL=http://localhost:8000/api/v1
ARG VITE_WS_URL=ws://localhost:8000
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_WS_URL=$VITE_WS_URL

COPY package*.json ./
RUN npm install

COPY . .
# We use a simple dev server for this lab environment, but build-stage is here for completeness
RUN npm run build

# Production stage
FROM node:20-alpine

WORKDIR /app

# Install 'serve' to serve the static build
RUN npm install -g serve

COPY --from=build-stage /app/dist /app/dist

EXPOSE 5173

# Serve the built app on port 5173
CMD ["serve", "-s", "dist", "-l", "5173"]
