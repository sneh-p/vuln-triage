FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary

COPY agents/_lib/ /app/agents/_lib/
COPY agents/correlator/ /app/agents/correlator/

ENV PYTHONPATH=/app/agents

ENTRYPOINT ["python", "agents/correlator/app.py"]
