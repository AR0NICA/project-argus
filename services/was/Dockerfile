FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df
ARG ARGUS_SOURCE_REVISION=unknown
ARG ARGUS_BUILD_CREATED=unknown
LABEL org.opencontainers.image.title="argus-was" \
      org.opencontainers.image.revision="$ARGUS_SOURCE_REVISION" \
      org.opencontainers.image.created="$ARGUS_BUILD_CREATED" \
      org.opencontainers.image.source="project-argus"
WORKDIR /app
COPY app.py /app/app.py
COPY requirements.txt /app/requirements.txt
# mysql-connector-python is hash-locked in requirements.txt.
RUN pip install --no-cache-dir --require-hashes -r /app/requirements.txt
EXPOSE 8081
CMD ["python", "/app/app.py"]
