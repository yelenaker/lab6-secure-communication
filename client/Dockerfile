FROM python:3.12-slim

WORKDIR /app

COPY shared /app/shared
COPY client /app/client
COPY client/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir -r /app/requirements.txt

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1
ENV SERVER_URL=http://server:8000

CMD ["python", "-m", "client.app.main"]
