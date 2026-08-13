locals {
  db_identifier    = "${var.name_prefix}-mysql"
  native_log_types = toset(["error", "general", "slowquery"])
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-rds"
  subnet_ids = var.data_subnet_ids
  tags       = merge(var.tags, { Component = "data", Name = "${var.name_prefix}-rds" })
}

resource "aws_db_parameter_group" "this" {
  name   = "${var.name_prefix}-mysql84"
  family = "mysql8.4"
  parameter {
    name         = "general_log"
    value        = "1"
    apply_method = "immediate"
  }
  parameter {
    name         = "slow_query_log"
    value        = "1"
    apply_method = "immediate"
  }
  parameter {
    name         = "log_output"
    value        = "FILE"
    apply_method = "immediate"
  }
  tags = merge(var.tags, { Component = "data", Name = "${var.name_prefix}-mysql84" })
}

resource "aws_cloudwatch_log_group" "native" {
  for_each          = local.native_log_types
  name              = "/aws/rds/instance/${local.db_identifier}/${each.value}"
  retention_in_days = var.native_log_retention_in_days
  tags              = merge(var.tags, { Component = "data", Source = "rds-${each.value}" })
}

resource "aws_db_instance" "this" {
  identifier                      = local.db_identifier
  engine                          = "mysql"
  engine_version                  = "8.4.10"
  instance_class                  = var.instance_class
  allocated_storage               = var.allocated_storage
  storage_encrypted               = true
  db_name                         = "argus_synthetic"
  username                        = "argus_schema_admin"
  manage_master_user_password     = true
  db_subnet_group_name            = aws_db_subnet_group.this.name
  vpc_security_group_ids          = [var.rds_security_group_id]
  parameter_group_name            = aws_db_parameter_group.this.name
  publicly_accessible             = false
  backup_retention_period         = var.backup_retention_days
  deletion_protection             = var.deletion_protection
  skip_final_snapshot             = var.skip_final_snapshot
  final_snapshot_identifier       = var.skip_final_snapshot ? null : (var.final_snapshot_identifier != "" ? var.final_snapshot_identifier : null)
  auto_minor_version_upgrade      = false
  copy_tags_to_snapshot           = true
  enabled_cloudwatch_logs_exports = ["error", "general", "slowquery"]
  tags                            = merge(var.tags, { Component = "data", Name = "${var.name_prefix}-mysql" })

  depends_on = [aws_cloudwatch_log_group.native]
}
