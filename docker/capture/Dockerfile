FROM mcr.microsoft.com/playwright/python:v1.61.0-noble@sha256:a9731514f24121d1dcd25d58d0a38146646d290a5998fd80d3e533e7b5e21c69

RUN python -m pip install --no-cache-dir playwright==1.61.0
RUN id -u pwuser >/dev/null 2>&1 || useradd --create-home --shell /bin/bash pwuser

COPY src/domain_abuse_toolkit/capture_worker.py /opt/domain-abuse-toolkit/capture_worker.py

USER pwuser
WORKDIR /tmp
ENTRYPOINT ["python", "-I", "/opt/domain-abuse-toolkit/capture_worker.py"]
