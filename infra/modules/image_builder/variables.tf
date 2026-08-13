variable "name_prefix" { type = string }
variable "aws_region" { type = string }
variable "parent_ami_id" { type = string }
variable "builder_subnet_id" { type = string }
variable "builder_security_group_id" { type = string }
variable "component_version" { type = string }
variable "recipe_version" { type = string }
variable "tags" { type = map(string) }
