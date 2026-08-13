resource "aws_iam_role" "web_test" {
  name = "${var.name_prefix}-web-test"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { Component = "compute", Name = "${var.name_prefix}-web-test" })
}

resource "aws_iam_role" "was_test" {
  name = "${var.name_prefix}-was-test"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { Component = "compute", Name = "${var.name_prefix}-was-test" })
}

resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web_test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "was_ssm" {
  role       = aws_iam_role.was_test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "web_runtime" {
  statement {
    sid       = "GetWebBootstrapSentinel"
    actions   = ["ssm:GetParameter"]
    resources = [var.web_sentinel_parameter_arn]
  }
  statement {
    sid       = "GetEcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "PullWebImageByDigest"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [var.gateway_ecr_repository_arn, var.web_ecr_repository_arn]
  }
}

data "aws_iam_policy_document" "was_runtime" {
  statement {
    sid       = "GetExactD1ReaderRuntimeSecret"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.was_d1_reader_secret_arn]
  }
  statement {
    sid       = "GetEcrAuthorizationToken"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid = "PullWasImageByDigest"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:GetDownloadUrlForLayer",
    ]
    resources = [var.was_ecr_repository_arn]
  }
}

data "aws_iam_policy_document" "was_seed_master_read" {
  count = var.enable_seed_master_secret_read ? 1 : 0
  statement {
    sid       = "TemporaryFixedSeedMasterSecretRead"
    actions   = ["secretsmanager:GetSecretValue"]
    resources = [var.rds_master_secret_arn]
  }
  statement {
    sid       = "TemporaryFixedSeedReaderSecretWrite"
    actions   = ["secretsmanager:PutSecretValue"]
    resources = [var.was_d1_reader_secret_arn]
  }
  statement {
    sid       = "PullSeedImageByDigest"
    actions   = ["ecr:BatchCheckLayerAvailability", "ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"]
    resources = [var.seed_ecr_repository_arn]
  }
}

resource "aws_iam_role_policy" "web_runtime" {
  name   = "${var.name_prefix}-web-runtime"
  role   = aws_iam_role.web_test.id
  policy = data.aws_iam_policy_document.web_runtime.json
}

resource "aws_iam_role_policy" "was_runtime" {
  name   = "${var.name_prefix}-was-runtime"
  role   = aws_iam_role.was_test.id
  policy = data.aws_iam_policy_document.was_runtime.json
}

resource "aws_iam_role_policy" "was_seed_master_read" {
  count  = var.enable_seed_master_secret_read ? 1 : 0
  name   = "${var.name_prefix}-was-temporary-seed-master-read"
  role   = aws_iam_role.was_test.id
  policy = data.aws_iam_policy_document.was_seed_master_read[0].json
}

data "aws_iam_policy_document" "web_logs" {
  statement {
    actions   = ["logs:DescribeLogStreams"]
    resources = var.web_log_group_arns
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for log_group_arn in var.web_log_group_arns : "${log_group_arn}:*"]
  }
}

data "aws_iam_policy_document" "was_logs" {
  statement {
    actions   = ["logs:DescribeLogStreams"]
    resources = var.was_log_group_arns
  }
  statement {
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = [for log_group_arn in var.was_log_group_arns : "${log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "web_logs" {
  name   = "${var.name_prefix}-web-log-write"
  role   = aws_iam_role.web_test.id
  policy = data.aws_iam_policy_document.web_logs.json
}

resource "aws_iam_role_policy" "was_logs" {
  name   = "${var.name_prefix}-was-log-write"
  role   = aws_iam_role.was_test.id
  policy = data.aws_iam_policy_document.was_logs.json
}

resource "aws_iam_instance_profile" "web" {
  name = "${var.name_prefix}-web"
  role = aws_iam_role.web_test.name
}

resource "aws_iam_instance_profile" "was" {
  name = "${var.name_prefix}-was"
  role = aws_iam_role.was_test.name
}

resource "aws_instance" "web" {
  ami                         = var.web_ami_id
  instance_type               = var.web_instance_type
  subnet_id                   = var.web_subnet_id
  vpc_security_group_ids      = [var.web_security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.web.name
  associate_public_ip_address = false
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/web-user-data.sh.tftpl", {
    aws_region                       = var.aws_region
    ecr_registry                     = var.ecr_registry
    gateway_image_uri                = "${var.gateway_ecr_repository_url}@${var.gateway_image_digest}"
    web_image_uri                    = "${var.web_ecr_repository_url}@${var.web_image_digest}"
    web_sentinel_parameter_name      = var.web_sentinel_parameter_name
    canary_bucket_name               = var.canary_bucket_name
    canary_object_key                = var.canary_object_key
    canary_object_version_id         = var.canary_object_version_id
    was_private_ip                   = aws_instance.was.private_ip
    nginx_modsecurity_log_group_name = var.nginx_modsecurity_log_group_name
    web_log_group_name               = var.web_log_group_name
    d0_envelope_log_group_name       = var.d0_envelope_log_group_name
    host_log_group_name              = var.host_log_group_name
  }))
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  tags = merge(var.tags, { Component = "compute", Tier = "web", Name = "${var.name_prefix}-web" })
}

resource "aws_instance" "was" {
  ami                         = var.was_ami_id
  instance_type               = var.was_instance_type
  subnet_id                   = var.was_subnet_id
  private_ip                  = var.was_private_ip
  vpc_security_group_ids      = [var.was_security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.was.name
  associate_public_ip_address = false
  user_data_base64 = base64gzip(templatefile("${path.module}/templates/was-user-data.sh.tftpl", {
    aws_region               = var.aws_region
    ecr_registry             = var.ecr_registry
    was_image_uri            = "${var.was_ecr_repository_url}@${var.was_image_digest}"
    seed_image_uri           = "${var.seed_ecr_repository_url}@${var.seed_image_digest}"
    rds_endpoint             = var.rds_endpoint
    was_d1_reader_secret_arn = var.was_d1_reader_secret_arn
    was_log_group_name       = var.was_log_group_name
    host_log_group_name      = var.host_log_group_name
  }))
  user_data_replace_on_change = true
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 2
  }
  tags = merge(var.tags, { Component = "compute", Tier = "was", Name = "${var.name_prefix}-was" })
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = var.web_target_group_arn
  target_id        = aws_instance.web.id
  port             = var.web_port
}
