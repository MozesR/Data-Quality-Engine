FROM python:3.12-slim

WORKDIR /app
COPY services/mcp-server/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/mcp-server/app /app/app
COPY services/mcp-server/alembic /app/alembic
COPY services/mcp-server/alembic.ini /app/alembic.ini
COPY config /app/config

EXPOSE 8002
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8002"]
