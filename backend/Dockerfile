FROM python:3.12-slim

# System deps: WeasyPrint (cairo/pango) + Playwright + general tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    shared-mime-info \
    wget \
    unzip \
    ca-certificates \
    gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright's Chromium browser + its OS-level dependencies
RUN playwright install --with-deps chromium

# Install Nuclei (optional DAST scanner — pipeline skips gracefully if absent)
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.2.9/nuclei_3.2.9_linux_amd64.zip \
    && unzip -q nuclei_3.2.9_linux_amd64.zip nuclei \
    && mv nuclei /usr/local/bin/nuclei \
    && chmod +x /usr/local/bin/nuclei \
    && rm nuclei_3.2.9_linux_amd64.zip

COPY . .

RUN mkdir -p screenshots

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
