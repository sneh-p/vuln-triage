FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary requests cryptography

COPY agents/_lib/ /app/agents/_lib/
COPY agents/ticketer/ /app/agents/ticketer/

ENV PYTHONPATH=/app/agents

ENTRYPOINT ["python", "agents/ticketer/app.py"]
