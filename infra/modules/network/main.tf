data "aws_region" "current" {}

locals {
  subnet_specs = {
    edge_a = { cidr = var.subnet_cidrs.edge_a, az = var.availability_zones[0], tier = "edge" }
    edge_b = { cidr = var.subnet_cidrs.edge_b, az = var.availability_zones[1], tier = "edge" }
    web_a  = { cidr = var.subnet_cidrs.web_a, az = var.availability_zones[0], tier = "web" }
    web_b  = { cidr = var.subnet_cidrs.web_b, az = var.availability_zones[1], tier = "web" }
    was_a  = { cidr = var.subnet_cidrs.was_a, az = var.availability_zones[0], tier = "was" }
    was_b  = { cidr = var.subnet_cidrs.was_b, az = var.availability_zones[1], tier = "was" }
    data_a = { cidr = var.subnet_cidrs.data_a, az = var.availability_zones[0], tier = "data" }
    data_b = { cidr = var.subnet_cidrs.data_b, az = var.availability_zones[1], tier = "data" }
  }

  tags = merge(var.tags, { Component = "network" })
}

resource "aws_vpc" "this" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${var.name_prefix}-vpc" })
}

resource "aws_internet_gateway" "edge" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-edge-igw" })
}

resource "aws_subnet" "this" {
  for_each = local.subnet_specs

  vpc_id                  = aws_vpc.this.id
  cidr_block              = each.value.cidr
  availability_zone       = each.value.az
  map_public_ip_on_launch = false
  tags = merge(local.tags, {
    Name = "${var.name_prefix}-${replace(each.key, "_", "-")}"
    Tier = each.value.tier
  })
}

resource "aws_route_table" "edge" {
  vpc_id = aws_vpc.this.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.edge.id
  }
  tags = merge(local.tags, { Name = "${var.name_prefix}-edge-rt" })
}

resource "aws_route_table" "web" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-web-rt" })
}

resource "aws_route_table" "was" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-was-rt" })
}

resource "aws_route_table" "data" {
  vpc_id = aws_vpc.this.id
  tags   = merge(local.tags, { Name = "${var.name_prefix}-data-rt" })
}

resource "aws_route_table_association" "this" {
  for_each = {
    edge_a = aws_route_table.edge.id
    edge_b = aws_route_table.edge.id
    web_a  = aws_route_table.web.id
    web_b  = aws_route_table.web.id
    was_a  = aws_route_table.was.id
    was_b  = aws_route_table.was.id
    data_a = aws_route_table.data.id
    data_b = aws_route_table.data.id
  }

  subnet_id      = aws_subnet.this[each.key].id
  route_table_id = each.value
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.this.id
  service_name      = "com.amazonaws.${data.aws_region.current.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.web.id]
  tags              = merge(local.tags, { Name = "${var.name_prefix}-s3-gateway" })
}

resource "aws_security_group" "vpce" {
  name        = "${var.name_prefix}-vpce"
  description = "ARGUS private interface endpoint ingress only"
  vpc_id      = aws_vpc.this.id
  ingress     = []
  egress      = []
  tags        = merge(local.tags, { Name = "${var.name_prefix}-vpce" })
}

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "Only approved test CIDRs may reach public HTTPS"
  vpc_id      = aws_vpc.this.id
  ingress     = []
  egress      = []
  tags        = merge(local.tags, { Name = "${var.name_prefix}-alb" })
}

resource "aws_security_group" "web" {
  name        = "${var.name_prefix}-web"
  description = "Private Web tier"
  vpc_id      = aws_vpc.this.id
  ingress     = []
  egress      = []
  tags        = merge(local.tags, { Name = "${var.name_prefix}-web" })
}

resource "aws_security_group" "was" {
  name        = "${var.name_prefix}-was"
  description = "Private WAS tier"
  vpc_id      = aws_vpc.this.id
  ingress     = []
  egress      = []
  tags        = merge(local.tags, { Name = "${var.name_prefix}-was" })
}

resource "aws_security_group" "rds" {
  name        = "${var.name_prefix}-rds"
  description = "Private RDS tier"
  vpc_id      = aws_vpc.this.id
  ingress     = []
  egress      = []
  tags        = merge(local.tags, { Name = "${var.name_prefix}-rds" })
}

resource "aws_vpc_security_group_ingress_rule" "alb_https" {
  for_each          = toset(var.allowed_test_cidrs)
  security_group_id = aws_security_group.alb.id
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Approved test client HTTPS"
}

resource "aws_vpc_security_group_egress_rule" "alb_to_web" {
  security_group_id            = aws_security_group.alb.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = var.web_port
  to_port                      = var.web_port
  ip_protocol                  = "tcp"
  description                  = "ALB to Web only"
}

resource "aws_vpc_security_group_ingress_rule" "web_from_alb" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.alb.id
  from_port                    = var.web_port
  to_port                      = var.web_port
  ip_protocol                  = "tcp"
  description                  = "ALB to Web only"
}

resource "aws_vpc_security_group_egress_rule" "web_to_was_business" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.was.id
  from_port                    = var.was_business_port
  to_port                      = var.was_business_port
  ip_protocol                  = "tcp"
  description                  = "Web to WAS business API"
}

resource "aws_vpc_security_group_egress_rule" "web_to_was_admin" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.was.id
  from_port                    = var.was_admin_port
  to_port                      = var.was_admin_port
  ip_protocol                  = "tcp"
  description                  = "Web to BASE WAS admin API"
}

resource "aws_vpc_security_group_ingress_rule" "was_from_web_business" {
  security_group_id            = aws_security_group.was.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = var.was_business_port
  to_port                      = var.was_business_port
  ip_protocol                  = "tcp"
  description                  = "Web business API only"
}

resource "aws_vpc_security_group_ingress_rule" "was_from_web_admin" {
  security_group_id            = aws_security_group.was.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = var.was_admin_port
  to_port                      = var.was_admin_port
  ip_protocol                  = "tcp"
  description                  = "Web BASE admin API only"
}

resource "aws_vpc_security_group_egress_rule" "was_to_rds" {
  security_group_id            = aws_security_group.was.id
  referenced_security_group_id = aws_security_group.rds.id
  from_port                    = var.db_port
  to_port                      = var.db_port
  ip_protocol                  = "tcp"
  description                  = "WAS to RDS only"
}

resource "aws_vpc_security_group_ingress_rule" "rds_from_was" {
  security_group_id            = aws_security_group.rds.id
  referenced_security_group_id = aws_security_group.was.id
  from_port                    = var.db_port
  to_port                      = var.db_port
  ip_protocol                  = "tcp"
  description                  = "WAS to RDS only"
}

resource "aws_vpc_security_group_egress_rule" "web_to_vpce" {
  security_group_id            = aws_security_group.web.id
  referenced_security_group_id = aws_security_group.vpce.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Web to approved VPC endpoints"
}

resource "aws_vpc_security_group_egress_rule" "web_to_s3_gateway" {
  security_group_id = aws_security_group.web.id
  prefix_list_id    = aws_vpc_endpoint.s3.prefix_list_id
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
  description       = "Web exact-version canary read through S3 gateway"
}

resource "aws_vpc_security_group_egress_rule" "was_to_vpce" {
  security_group_id            = aws_security_group.was.id
  referenced_security_group_id = aws_security_group.vpce.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "WAS to approved VPC endpoints"
}

resource "aws_vpc_security_group_ingress_rule" "vpce_from_web" {
  security_group_id            = aws_security_group.vpce.id
  referenced_security_group_id = aws_security_group.web.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "Web private endpoint traffic"
}

resource "aws_vpc_security_group_ingress_rule" "vpce_from_was" {
  security_group_id            = aws_security_group.vpce.id
  referenced_security_group_id = aws_security_group.was.id
  from_port                    = 443
  to_port                      = 443
  ip_protocol                  = "tcp"
  description                  = "WAS private endpoint traffic"
}

resource "aws_vpc_endpoint" "interface" {
  for_each = toset(["ssm", "ssmmessages", "logs"])

  vpc_id              = aws_vpc.this.id
  service_name        = "com.amazonaws.${data.aws_region.current.region}.${each.value}"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = [aws_subnet.this["web_a"].id, aws_subnet.this["web_b"].id]
  security_group_ids  = [aws_security_group.vpce.id]
  tags                = merge(local.tags, { Name = "${var.name_prefix}-${each.value}-vpce" })
}
