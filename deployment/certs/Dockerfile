FROM alpine:3.19
RUN apk add --no-cache openssl
COPY generate.sh /generate.sh
RUN sed -i 's/\r//' /generate.sh && chmod +x /generate.sh
ENTRYPOINT ["/generate.sh"]
