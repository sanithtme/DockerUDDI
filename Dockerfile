FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1 PYTHONPATH=/app/backend/src INFOBLOX_DEMO_WORKSPACE=/workspace
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 dnsutils ca-certificates && rm -rf /var/lib/apt/lists/*
COPY . /app
RUN pip install --no-cache-dir 'scapy>=2.5,<3' 'PyYAML>=6.0' 'boto3>=1.34' 'requests>=2.31' && \
    printf '#!/bin/sh\nexec python -c '\''import sys; from demo_launcher import main; sys.exit(main())'\'' "$@"\n' > /usr/local/bin/demo && chmod +x /usr/local/bin/demo && \
    demo --help >/dev/null
CMD ["sleep","infinity"]
