variable "name_prefix" { type = string }
variable "vpc_cidr" { type = string }
variable "availability_zones" { type = list(string) }
variable "allowed_test_cidrs" { type = list(string) }
variable "web_port" { type = number }
variable "was_business_port" { type = number }
variable "was_admin_port" { type = number }
variable "db_port" { type = number }
variable "tags" { type = map(string) }

variable "subnet_cidrs" {
  type = object({
    edge_a = string
    edge_b = string
    web_a  = string
    web_b  = string
    was_a  = string
    was_b  = string
    data_a = string
    data_b = string
  })
}
