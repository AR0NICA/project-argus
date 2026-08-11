data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "web_test" {
  name               = "${var.name_prefix}-web-test"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = merge(var.tags, { Component = "compute", Name = "${var.name_prefix}-web-test" })
}

resource "aws_iam_role" "was_test" {
  name               = "${var.name_prefix}-was-test"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  tags               = merge(var.tags, { Component = "compute", Name = "${var.name_prefix}-was-test" })
}

resource "aws_iam_role_policy_attachment" "web_ssm" {
  role       = aws_iam_role.web_test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "was_ssm" {
  role       = aws_iam_role.was_test.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
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
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags = merge(var.tags, { Component = "compute", Tier = "web", Name = "${var.name_prefix}-web" })
}

resource "aws_instance" "was" {
  ami                         = var.was_ami_id
  instance_type               = var.was_instance_type
  subnet_id                   = var.was_subnet_id
  vpc_security_group_ids      = [var.was_security_group_id]
  iam_instance_profile        = aws_iam_instance_profile.was.name
  associate_public_ip_address = false
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }
  tags = merge(var.tags, { Component = "compute", Tier = "was", Name = "${var.name_prefix}-was" })
}

resource "aws_lb_target_group_attachment" "web" {
  target_group_arn = var.web_target_group_arn
  target_id        = aws_instance.web.id
  port             = var.web_port
}
