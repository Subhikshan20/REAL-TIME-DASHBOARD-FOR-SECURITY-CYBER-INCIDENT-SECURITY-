# SOC Dashboard — reproducible, non-root container image.
# Build from the PROJECT ROOT (the build context must include src/):
#   docker build -f docker/Dockerfile -t soc-dashboard .
#   docker run -p 8501:8501 soc-dashboard
# Or simply:  docker compose -f docker/docker-compose.yml up --build
FROM python:3.14-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    SOC_LOG_LEVEL=INFO

WORKDIR /app

# Install dependencies first so they are cached independently of source changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application.
COPY . .

# Run as an unprivileged user (least privilege). /app is owned by the user so the
# app can still write the generated dataset / incident state at runtime.
RUN useradd --create-home --uid 10001 appuser \
    && chown -R appuser:appuser /app
USER appuser

EXPOSE 8501

# Streamlit's built-in health endpoint makes a clean container healthcheck.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; urllib.request.urlopen('http://localhost:8501/_stcore/health'); sys.exit(0)" || exit 1

CMD ["streamlit", "run", "src/app.py", \
     "--server.address=0.0.0.0", "--server.port=8501", "--server.headless=true"]
