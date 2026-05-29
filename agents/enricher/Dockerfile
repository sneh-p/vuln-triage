FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary requests

COPY agents/_lib/ /app/agents/_lib/
COPY agents/enricher/ /app/agents/enricher/

ENV PYTHONPATH=/app/agents

ENTRYPOINT ["python", "agents/enricher/app.py"]
