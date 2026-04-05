FROM python:3.11-slim

LABEL maintainer="API Security Research"
LABEL description="API Misconfiguration Scanner — For Authorized Research Only"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Create reports directory
RUN mkdir -p reports

# Expose lab server port
EXPOSE 5000

# Default: show help
ENTRYPOINT ["python", "scanner.py"]
CMD ["--help"]
