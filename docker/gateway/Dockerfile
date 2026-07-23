FROM nginx:1.31.3-alpine-slim@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752

COPY docker/gateway/nginx.conf /etc/nginx/nginx.conf

USER nginx

EXPOSE 8080

ENTRYPOINT ["nginx", "-g", "daemon off;"]
