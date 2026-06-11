FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose FastAPI + all honeypot service ports
EXPOSE 8000 2222 8080 2121

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]