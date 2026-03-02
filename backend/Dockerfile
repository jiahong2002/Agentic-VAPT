FROM python:3.12-slim-bookworm

# WeasyPrint + general tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf2.0-0 \
    libffi-dev \
    shared-mime-info \
    wget \
    unzip \
    ca-certificates \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Chromium runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxext6 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libdbus-1-3 \
    libatspi2.0-0 \
    libglib2.0-0 \
    libxcb1 \
    && rm -rf /var/lib/apt/lists/*

# Fonts
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-liberation \
    fonts-unifont \
    && rm -rf /var/lib/apt/lists/*

# libasound2 name changed to libasound2t64 in some Debian versions; try both
RUN apt-get update \
    && (apt-get install -y --no-install-recommends libasound2 || apt-get install -y --no-install-recommends libasound2t64) \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Download Chromium browser binary only (deps installed above)
RUN python -m playwright install chromium

# Install Nuclei — auto-detect arch, skip silently if unavailable
RUN ARCH=$(dpkg --print-architecture) \
    && wget -q "https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_${ARCH}.zip" \
    && unzip -q "nuclei_3.2.9_linux_${ARCH}.zip" nuclei \
    && mv nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm "nuclei_3.2.9_linux_${ARCH}.zip" \
    || true

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
