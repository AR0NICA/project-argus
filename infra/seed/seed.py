"""Idempotent, synthetic-only D1 database seed. No secret values are logged."""
import json
import os
import secrets

import boto3
import pymysql
from botocore.exceptions import ClientError


def secret(client, arn):
    value = client.get_secret_value(SecretId=arn)["SecretString"]
    return json.loads(value)


def existing_reader_password(client, arn):
    try:
        value = client.get_secret_value(SecretId=arn)["SecretString"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return None
    return value if isinstance(value, str) and value else None


def main():
    region = os.environ["AWS_REGION"]
    endpoint = os.environ["ARGUS_RDS_ENDPOINT"]
    secrets_client = boto3.client("secretsmanager", region_name=region)
    master = secret(secrets_client, os.environ["ARGUS_RDS_MASTER_SECRET_ARN"])
    reader_secret_arn = os.environ["ARGUS_D1_READER_SECRET_ARN"]
    previous_password = existing_reader_password(secrets_client, reader_secret_arn)
    reader_password = secrets.token_urlsafe(32)
    connection = pymysql.connect(host=endpoint, user=master["username"], password=master["password"], database="argus_synthetic", autocommit=True)
    try:
        with connection.cursor() as cursor:
            cursor.execute("CREATE TABLE IF NOT EXISTS d1_synthetic_records (record_id INT NOT NULL PRIMARY KEY, fixture_id VARCHAR(32) NOT NULL, category VARCHAR(32) NOT NULL, summary VARCHAR(128) NOT NULL)")
            cursor.execute("INSERT INTO d1_synthetic_records (record_id, fixture_id, category, summary) VALUES (1, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 01'), (2, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 02'), (3, 'BEN-D1-OBS-001', 'synthetic', 'D1 benign observation row 03') ON DUPLICATE KEY UPDATE fixture_id=VALUES(fixture_id), category=VALUES(category), summary=VALUES(summary)")
            cursor.execute("CREATE USER IF NOT EXISTS 'argus_d1_reader'@'%%' IDENTIFIED BY %s", (reader_password,))
            cursor.execute("ALTER USER 'argus_d1_reader'@'%%' IDENTIFIED BY %s", (reader_password,))
            cursor.execute("GRANT SELECT (record_id, fixture_id, category, summary) ON argus_synthetic.d1_synthetic_records TO 'argus_d1_reader'@'%'")
            cursor.execute("FLUSH PRIVILEGES")
    finally:
        connection.close()
    try:
        secrets_client.put_secret_value(SecretId=reader_secret_arn, SecretString=reader_password)
    except Exception:
        if previous_password:
            rollback = pymysql.connect(host=endpoint, user=master["username"], password=master["password"], database="argus_synthetic", autocommit=True)
            try:
                with rollback.cursor() as cursor:
                    cursor.execute("ALTER USER 'argus_d1_reader'@'%%' IDENTIFIED BY %s", (previous_password,))
            finally:
                rollback.close()
        raise
    print("argus_d1_seed_completed")


if __name__ == "__main__":
    main()
