resource "aws_iam_role" "builder" {
  name = "${var.name_prefix}-image-builder"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
  tags = merge(var.tags, { Component = "image-builder" })
}

resource "aws_iam_role_policy_attachment" "image_builder" {
  role       = aws_iam_role.builder.name
  policy_arn = "arn:aws:iam::aws:policy/EC2InstanceProfileForImageBuilder"
}

resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.builder.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "builder" {
  name = "${var.name_prefix}-image-builder"
  role = aws_iam_role.builder.name
}

resource "aws_imagebuilder_component" "runtime_tools" {
  name     = "${var.name_prefix}-runtime-tools"
  platform = "Linux"
  version  = var.component_version
  data     = <<-YAML
    name: ArgusRuntimeTools
    description: Install and verify private-runtime host prerequisites.
    schemaVersion: 1.0
    phases:
      - name: build
        steps:
          - name: InstallRuntimeTools
            action: ExecuteBash
            inputs:
              commands:
                - dnf install -y audit-3.1.5-1.amzn2023.0.2 amazon-cloudwatch-agent-1.300069.1-1.amzn2023
                - install -d -m 0755 /usr/local/lib/docker/cli-plugins
                - curl -fL --retry 3 --proto '=https' --tlsv1.2 https://github.com/docker/compose/releases/download/v5.1.4/docker-compose-linux-x86_64 -o /usr/local/lib/docker/cli-plugins/docker-compose
                - echo '33b208d7e76639db742fae84b966cc01dacae58ca3fc4dabbc907045aefdf0c4  /usr/local/lib/docker/cli-plugins/docker-compose' | sha256sum --check --strict
                - chmod 0755 /usr/local/lib/docker/cli-plugins/docker-compose
                - systemctl enable docker
      - name: validate
        steps:
          - name: VerifyRuntimeTools
            action: ExecuteBash
            inputs:
              commands:
                - command -v docker
                - docker --version
                - docker compose version
                - test "$(docker compose version --short)" = "5.1.4"
                - command -v aws
                - aws --version
                - command -v auditctl
                - rpm -q audit-3.1.5-1.amzn2023.0.2 amazon-cloudwatch-agent-1.300069.1-1.amzn2023
                - test -x /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl
  YAML
  tags     = merge(var.tags, { Component = "image-builder" })
}

resource "aws_imagebuilder_image_recipe" "runtime" {
  name         = "${var.name_prefix}-runtime"
  parent_image = var.parent_ami_id
  version      = var.recipe_version
  component { component_arn = aws_imagebuilder_component.runtime_tools.arn }
  block_device_mapping {
    device_name = "/dev/xvda"
    ebs {
      delete_on_termination = true
      encrypted             = true
      volume_size           = 30
      volume_type           = "gp3"
    }
  }
  tags = merge(var.tags, { Component = "image-builder", Runtime = "d1" })
}

resource "aws_imagebuilder_infrastructure_configuration" "runtime" {
  name                          = "${var.name_prefix}-runtime"
  instance_profile_name         = aws_iam_instance_profile.builder.name
  instance_types                = ["t3.small"]
  subnet_id                     = var.builder_subnet_id
  security_group_ids            = [var.builder_security_group_id]
  terminate_instance_on_failure = true
  tags                          = merge(var.tags, { Component = "image-builder", Builder = "temporary-public" })
}

resource "aws_imagebuilder_distribution_configuration" "runtime" {
  name = "${var.name_prefix}-runtime"
  distribution {
    region = var.aws_region
    ami_distribution_configuration {
      name     = "${var.name_prefix}-runtime-{{ imagebuilder:buildDate }}"
      ami_tags = merge(var.tags, { Component = "runtime-ami", ParentAmi = var.parent_ami_id })
    }
  }
}

resource "aws_imagebuilder_image" "runtime" {
  image_recipe_arn                 = aws_imagebuilder_image_recipe.runtime.arn
  infrastructure_configuration_arn = aws_imagebuilder_infrastructure_configuration.runtime.arn
  distribution_configuration_arn   = aws_imagebuilder_distribution_configuration.runtime.arn
  enhanced_image_metadata_enabled  = true
  tags                             = merge(var.tags, { Component = "runtime-ami", Build = "immutable" })
}
