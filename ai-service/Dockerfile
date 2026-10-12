FROM python:3.11-slim
WORKDIR /app
COPY ai-service/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ai-service/inference.py .
COPY ai-service/model/ ./model/
ENV MODEL_DIR=/app/model
EXPOSE 8001
CMD ["uvicorn", "inference:app", "--host", "0.0.0.0", "--port", "8001"]
