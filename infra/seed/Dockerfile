FROM python:3.12-alpine@sha256:6d43704baacd1bfbe7c295d7f13079d5d8104ed33568873133f8fc69980419df

COPY requirements.txt /opt/argus/requirements.txt
RUN pip install --no-cache-dir --require-hashes -r /opt/argus/requirements.txt
COPY seed.py /opt/argus/seed.py
USER 65532:65532
ENTRYPOINT ["python", "/opt/argus/seed.py"]
