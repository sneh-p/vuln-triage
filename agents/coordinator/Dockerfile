FROM python:3.11-slim

WORKDIR /app

RUN pip install --no-cache-dir psycopg2-binary fastapi uvicorn apscheduler requests python-multipart passlib[bcrypt] itsdangerous cryptography

COPY agents/_lib/ /app/agents/_lib/
COPY agents/coordinator/ /app/agents/coordinator/

ENV PYTHONPATH=/app/agents

EXPOSE 8080

ENTRYPOINT ["python", "agents/coordinator/app.py"]
