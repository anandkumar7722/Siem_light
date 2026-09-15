# ==============================================================================
# Lightweight Explainable SIEM (Siem_light) Dockerfile
# Optimized for lightweight CPU execution & instant multi-platform deployment
# ==============================================================================

FROM python:3.10-slim

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive

# Set container working directory
WORKDIR /app

# Install minimal OS build tools required for compiled dependencies (e.g., SHAP, LIME)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy project files into container
COPY . /app/

# Ensure entrypoint script is executable
RUN chmod +x /app/entrypoint.sh

# Expose Streamlit dashboard port
EXPOSE 8501

# Healthcheck to verify the Streamlit dashboard server is responsive
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default Entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]
