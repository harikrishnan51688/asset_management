FROM python:3.11-slim

WORKDIR /app

# Install basic network utilities
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose HTTP Web Visualizer & REST API Port
EXPOSE 8080

# Start HTTP Server by default
CMD ["python3", "server.py"]
