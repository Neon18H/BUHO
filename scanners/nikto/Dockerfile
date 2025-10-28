FROM debian:stable-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends nikto perl \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["nikto"]
