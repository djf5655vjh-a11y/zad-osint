FROM python:3.12-slim
RUN useradd -r -s /usr/sbin/nologin zadweb \
 && apt-get update && apt-get install -y --no-install-recommends gcc libffi-dev libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV DATA_DIR=/data PYTHONUNBUFFERED=1
CMD ["sh", "./start.sh"]
