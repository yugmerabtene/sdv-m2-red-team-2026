FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    default-mysql-client netcat-openbsd curl dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/

EXPOSE 80

CMD ["python", "app.py"]
