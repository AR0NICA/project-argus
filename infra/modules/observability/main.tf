resource "terraform_data" "bucket_name_contract" {
  input = {
    evidence        = var.evidence_bucket_name
    alb_access_logs = var.alb_access_log_bucket_name
  }

  lifecycle {
    precondition {
      condition     = var.evidence_bucket_name != var.alb_access_log_bucket_name
      error_message = "Evidence and ALB access-log buckets must use distinct frozen names."
    }
  }
}

data "aws_iam_policy_document" "evidence_kms" {
  statement {
    sid       = "EnableAccountKeyAdministration"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${var.aws_account_id}:root"]
    }
  }
  statement {
    sid       = "AllowCloudTrailEncryption"
    effect    = "Allow"
    actions   = ["kms:GenerateDataKey*", "kms:DescribeKey"]
    resources = ["*"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_kms_key" "evidence" {
  description             = "${var.name_prefix} D1 evidence encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.evidence_kms.json
  tags                    = local.common_tags
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/${var.name_prefix}-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

resource "aws_s3_bucket" "evidence" {
  bucket        = var.evidence_bucket_name
  force_destroy = false
  tags          = local.common_tags

  depends_on = [terraform_data.bucket_name_contract]
}

resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    id     = "retain-versioned-evidence"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = var.retention_in_days }
  }
}

data "aws_iam_policy_document" "evidence_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [aws_s3_bucket.evidence.arn, "${aws_s3_bucket.evidence.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid     = "AllowCloudTrailAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.evidence.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
  statement {
    sid     = "AllowCloudTrailWrite"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.evidence.arn}/AWSLogs/${var.aws_account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.aws_account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = data.aws_iam_policy_document.evidence_bucket.json
}

resource "aws_s3_bucket" "alb_access" {
  bucket        = var.alb_access_log_bucket_name
  force_destroy = false
  tags          = merge(local.common_tags, { Purpose = "alb-access-log-delivery" })

  depends_on = [terraform_data.bucket_name_contract]
}

resource "aws_s3_bucket_public_access_block" "alb_access" {
  bucket                  = aws_s3_bucket.alb_access.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "alb_access" {
  bucket = aws_s3_bucket.alb_access.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_versioning" "alb_access" {
  bucket = aws_s3_bucket.alb_access.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "alb_access" {
  bucket = aws_s3_bucket.alb_access.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "alb_access" {
  bucket = aws_s3_bucket.alb_access.id
  rule {
    id     = "retain-versioned-alb-access-logs"
    status = "Enabled"
    filter {}
    noncurrent_version_expiration { noncurrent_days = var.retention_in_days }
  }
}

data "aws_iam_policy_document" "alb_access_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    resources = [aws_s3_bucket.alb_access.arn, "${aws_s3_bucket.alb_access.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid     = "AllowAlbAccessLogDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["logdelivery.elasticloadbalancing.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.alb_access.arn}/${var.alb_access_log_prefix}/AWSLogs/${var.aws_account_id}/*"]
  }
}

resource "aws_s3_bucket_policy" "alb_access" {
  bucket = aws_s3_bucket.alb_access.id
  policy = data.aws_iam_policy_document.alb_access_bucket.json
}

resource "aws_cloudwatch_log_group" "source" {
  for_each          = local.log_sources
  name              = "/argus/${lower(var.environment)}/${each.key}"
  retention_in_days = var.retention_in_days
  tags              = merge(local.common_tags, { Source = each.key })
}

data "aws_iam_policy_document" "cloudtrail_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "cloudtrail" {
  name               = "${var.name_prefix}-cloudtrail-logs"
  assume_role_policy = data.aws_iam_policy_document.cloudtrail_assume.json
  tags               = local.common_tags
}
resource "aws_iam_role_policy" "cloudtrail" {
  name   = "${var.name_prefix}-cloudtrail-logs"
  role   = aws_iam_role.cloudtrail.id
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.source["cloudtrail"].arn}:*" }] })
}

data "aws_iam_policy_document" "flow_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["vpc-flow-logs.amazonaws.com"]
    }
  }
}
resource "aws_iam_role" "flow" {
  name               = "${var.name_prefix}-flow-logs"
  assume_role_policy = data.aws_iam_policy_document.flow_assume.json
  tags               = local.common_tags
}
resource "aws_iam_role_policy" "flow" {
  name = "${var.name_prefix}-flow-logs"
  role = aws_iam_role.flow.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:DescribeLogStreams", "logs:PutLogEvents"], Resource = "${aws_cloudwatch_log_group.source["vpc_flow"].arn}:*" },
      { Effect = "Allow", Action = ["logs:DescribeLogGroups"], Resource = "*" }
    ]
  })
}

resource "aws_flow_log" "vpc" {
  count                    = var.enable_vpc_flow_logs ? 1 : 0
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.source["vpc_flow"].arn
  iam_role_arn             = aws_iam_role.flow.arn
  traffic_type             = "ALL"
  max_aggregation_interval = 60
  vpc_id                   = var.vpc_id
  tags                     = merge(local.common_tags, { Source = "vpc-flow" })
}

resource "aws_cloudtrail" "d1" {
  name                          = "${var.name_prefix}-d1"
  s3_bucket_name                = aws_s3_bucket.evidence.id
  kms_key_id                    = aws_kms_key.evidence.arn
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.source["cloudtrail"].arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail.arn
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = false
  dynamic "event_selector" {
    for_each = var.enable_s3_getobject_data_events ? [] : [1]
    content {
      include_management_events = true
      read_write_type           = "All"
    }
  }
  dynamic "advanced_event_selector" {
    for_each = var.enable_s3_getobject_data_events ? [1] : []
    content {
      name = "ManagementEvents"
      field_selector {
        field  = "eventCategory"
        equals = ["Management"]
      }
    }
  }
  dynamic "advanced_event_selector" {
    for_each = var.enable_s3_getobject_data_events ? [var.s3_getobject_resource_arn] : []
    content {
      name = "ScopedS3GetObject"
      field_selector {
        field  = "eventCategory"
        equals = ["Data"]
      }
      field_selector {
        field  = "resources.type"
        equals = ["AWS::S3::Object"]
      }
      field_selector {
        field  = "eventName"
        equals = ["GetObject"]
      }
      field_selector {
        field  = "readOnly"
        equals = ["true"]
      }
      field_selector {
        field       = "resources.ARN"
        starts_with = [advanced_event_selector.value]
      }
    }
  }
  lifecycle {
    precondition {
      condition     = !var.enable_s3_getobject_data_events || can(regex("^arn:aws[a-z-]*:s3:::[^/]+/.+", var.s3_getobject_resource_arn))
      error_message = "Scoped S3 data events require an S3 object or prefix ARN, not an empty or bucket-only ARN."
    }
  }
  depends_on = [aws_s3_bucket_policy.evidence, aws_iam_role_policy.cloudtrail]
  tags       = local.common_tags
}
