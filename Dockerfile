FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 dnsutils && rm -rf /var/lib/apt/lists/*
COPY . /app
RUN pip install --no-cache-dir .
ENV INFOBLOX_DEMO_WORKSPACE=/workspace
VOLUME ["/workspace"]
EXPOSE 8787
CMD ["demo","web","foreground","--host","0.0.0.0","--port","8787"]
