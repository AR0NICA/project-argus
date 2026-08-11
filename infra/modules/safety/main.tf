resource "terraform_data" "deployment_guard" {
  input = { environment = var.environment, name_prefix = var.name_prefix }
  lifecycle {
    precondition {
      condition     = contains(["BASE", "HARDENED"], var.environment)
      error_message = "Environment must be BASE or HARDENED."
    }
  }
}

resource "aws_budgets_budget" "this" {
  count        = var.enable_budget ? 1 : 0
  name         = "${var.name_prefix}-monthly"
  budget_type  = "COST"
  limit_amount = tostring(var.monthly_limit_usd)
  limit_unit   = "USD"
  time_unit    = "MONTHLY"
  notification {
    comparison_operator        = "GREATER_THAN"
    threshold                  = 100
    threshold_type             = "PERCENTAGE"
    notification_type          = "ACTUAL"
    subscriber_email_addresses = [var.budget_alert_email]
  }
}
