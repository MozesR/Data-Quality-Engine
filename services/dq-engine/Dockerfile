FROM python:3.12-slim

WORKDIR /app
COPY services/dq-engine/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY services/dq-engine/app /app/app
COPY config /app/config

EXPOSE 8001
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8001"]
