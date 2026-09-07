FROM python:3.11-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir flask requests gunicorn werkzeug

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT:-8080} api:app"]