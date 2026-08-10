FROM debian:13.6-slim@sha256:3a39a0592364683e6bab97937b72cad5a8fa6dcbbee90edb3bb48c7f8e94f258

RUN apt-get update && apt-get install -y --no-install-recommends \
    postfix=3.10.12-0+deb13u2 \
    libsasl2-2=2.1.28+dfsg1-9 \
    libsasl2-modules=2.1.28+dfsg1-9 \
    sasl2-bin=2.1.28+dfsg1-9 \
    netcat-openbsd=1.229-1 \
  && rm -rf /var/lib/apt/lists/*

COPY main.cf /etc/postfix/main.cf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 25 465 587

ENTRYPOINT ["/entrypoint.sh"]
