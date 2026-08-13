output "ami_id" { value = tolist(tolist(aws_imagebuilder_image.runtime.output_resources)[0].amis)[0].image }
output "image_arn" { value = aws_imagebuilder_image.runtime.arn }
output "parent_ami_id" { value = var.parent_ami_id }
