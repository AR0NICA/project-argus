resource "aws_lb" "this" {
  name                       = "${var.name_prefix}-alb"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [var.alb_security_group_id]
  subnets                    = var.edge_subnet_ids
  drop_invalid_header_fields = true
  enable_deletion_protection = var.enable_deletion_protection
  access_logs {
    bucket  = var.access_log_bucket_name
    prefix  = var.access_log_prefix
    enabled = true
  }
  tags = merge(var.tags, { Component = "edge", Name = "${var.name_prefix}-alb" })
}

resource "aws_lb_target_group" "web" {
  name        = "${var.name_prefix}-web"
  port        = var.web_port
  protocol    = "HTTP"
  target_type = "instance"
  vpc_id      = var.vpc_id
  health_check {
    path    = var.health_check_path
    matcher = "200-399"
  }
  tags = merge(var.tags, { Component = "edge", Name = "${var.name_prefix}-web-tg" })
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.this.arn
  port              = 443
  protocol          = "HTTPS"
  certificate_arn   = var.certificate_arn
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}
