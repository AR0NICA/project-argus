output "vpc_id" {
  value = aws_vpc.this.id
}

output "edge_subnet_ids" {
  value = [aws_subnet.this["edge_a"].id, aws_subnet.this["edge_b"].id]
}

output "web_subnet_ids" {
  value = [aws_subnet.this["web_a"].id, aws_subnet.this["web_b"].id]
}

output "was_subnet_ids" {
  value = [aws_subnet.this["was_a"].id, aws_subnet.this["was_b"].id]
}

output "data_subnet_ids" {
  value = [aws_subnet.this["data_a"].id, aws_subnet.this["data_b"].id]
}

output "security_group_ids" {
  value = {
    alb           = aws_security_group.alb.id
    web           = aws_security_group.web.id
    was           = aws_security_group.was.id
    rds           = aws_security_group.rds.id
    vpce          = aws_security_group.vpce.id
    image_builder = aws_security_group.image_builder.id
  }
}

output "s3_prefix_list_id" { value = aws_vpc_endpoint.s3.prefix_list_id }

output "s3_gateway_endpoint_id" {
  value = aws_vpc_endpoint.s3.id
}

output "s3_gateway_prefix_list_id" {
  value = aws_vpc_endpoint.s3.prefix_list_id
}

output "interface_endpoint_ids" {
  value = { for service, endpoint in aws_vpc_endpoint.interface : service => endpoint.id }
}
