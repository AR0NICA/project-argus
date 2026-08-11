variable "name_prefix" { type = string }
variable "bucket_name" { type = string }
variable "object_key" { type = string }
variable "object_version_id" { type = string }
variable "web_role_name" { type = string }
variable "attach_exact_version_policy" { type = bool }
variable "tags" { type = map(string) }
