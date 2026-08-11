resource "aws_s3_bucket" "this" {
  bucket        = var.bucket_name
  force_destroy = false
  tags          = merge(var.tags, { Component = "canary", Name = var.bucket_name })
}

resource "aws_s3_bucket_public_access_block" "this" {
  bucket                  = aws_s3_bucket.this.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "this" {
  bucket = aws_s3_bucket.this.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "this" {
  bucket = aws_s3_bucket.this.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "this" {
  bucket = aws_s3_bucket.this.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

data "aws_iam_policy_document" "transport" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [aws_s3_bucket.this.arn, "${aws_s3_bucket.this.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "transport" {
  bucket = aws_s3_bucket.this.id
  policy = data.aws_iam_policy_document.transport.json
}

data "aws_iam_policy_document" "web_canary" {
  count = var.attach_exact_version_policy ? 1 : 0
  statement {
    sid       = "ReadExactCanaryObjectVersion"
    actions   = ["s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.this.arn}/${var.object_key}"]
    condition {
      test     = "StringEquals"
      variable = "s3:VersionId"
      values   = [var.object_version_id]
    }
  }
}

resource "aws_iam_role_policy" "web_canary" {
  count  = var.attach_exact_version_policy ? 1 : 0
  name   = "${var.name_prefix}-exact-canary-read"
  role   = var.web_role_name
  policy = data.aws_iam_policy_document.web_canary[0].json

  depends_on = [aws_s3_bucket_versioning.this]
}
