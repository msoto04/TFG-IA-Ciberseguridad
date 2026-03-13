
FROM python:3.10-slim


RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*


RUN python3 -m pip install semgrep


WORKDIR /app



COPY requirements.txt .



RUN pip install --upgrade pip && \
    pip install --default-timeout=1000 --no-cache-dir -r requirements.txt


COPY . .


ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1


RUN mkdir -p /app/auditoria /app/resultados


EXPOSE 8000


CMD ["uvicorn", "Src.api:app", "--host", "0.0.0.0", "--port", "8000"]

