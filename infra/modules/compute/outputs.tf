output "web_instance_id" { value = aws_instance.web.id }
output "was_instance_id" { value = aws_instance.was.id }
output "web_test_role_arn" { value = aws_iam_role.web_test.arn }
output "web_test_role_name" { value = aws_iam_role.web_test.name }
