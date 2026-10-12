FROM node:20-alpine AS frontend-build
WORKDIR /build
COPY dashboard/frontend/package.json ./
RUN npm install
COPY dashboard/frontend/ ./
RUN npm run build

FROM python:3.11-slim
WORKDIR /app
COPY dashboard/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dashboard/backend/main.py .
COPY --from=frontend-build /build/dist ./static
ENV REPORTS_DIR=/app/reports STATIC_DIR=/app/static
EXPOSE 8080
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
