FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
WORKDIR /app
COPY app.py /app/app.py
RUN pip install --no-cache-dir mysql-connector-python==9.0.0
EXPOSE 8081
CMD ["python", "/app/app.py"]
