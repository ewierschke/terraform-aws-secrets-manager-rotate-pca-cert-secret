locals {
  lambda_name = "${var.project_name}-rotate-secret-ses-smtp-credentials"
  list_of_subnets_to_attach_lambda = (
    length(var.attach_to_vpc_explicit_list_of_subnet_ids) > 0 ? var.attach_to_vpc_explicit_list_of_subnet_ids :
    (var.attach_to_vpc_id != "" ? data.aws_subnets.private_subnets[0].ids : [])
  )
}

##############################
# Lambda
##############################
module "lambda" {
  #pinning to v8.8.0 as current during initial release
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v8.8.0"

  function_name = local.lambda_name

  description = "Secrets Manager Initiated rotation by Lamda Function of PCA issued certificate-${var.project_name}"
  handler     = "pca_cert_to_secret.lambda_handler"
  tags        = var.tags

  attach_policy_json = true
  policy_json        = data.aws_iam_policy_document.lambda.json

  artifacts_dir                     = var.lambda.artifacts_dir
  build_in_docker                   = var.lambda.build_in_docker
  cloudwatch_logs_retention_in_days = var.lambda.cloudwatch_logs_retention_in_days
  create_package                    = var.lambda.create_package
  ephemeral_storage_size            = var.lambda.ephemeral_storage_size
  ignore_source_code_hash           = var.lambda.ignore_source_code_hash
  local_existing_package            = var.lambda.local_existing_package
  logging_log_group                 = var.lambda.logging_log_group
  memory_size                       = var.lambda.memory_size
  recreate_missing_package          = var.lambda.recreate_missing_package
  runtime                           = var.lambda.runtime
  s3_bucket                         = var.lambda.s3_bucket
  s3_existing_package               = var.lambda.s3_existing_package
  s3_prefix                         = var.lambda.s3_prefix
  store_on_s3                       = var.lambda.store_on_s3
  timeout                           = var.lambda.timeout
  tracing_mode                      = var.lambda.tracing_mode
  use_existing_cloudwatch_log_group = var.lambda.use_existing_cloudwatch_log_group

  #conditionally set if local.list_of_subnets_to_attach_lambda evaluates larger than 0; subnet ids found w name *private* or explicitly list is provided
  vpc_subnet_ids         = length(local.list_of_subnets_to_attach_lambda) > 0 ? local.list_of_subnets_to_attach_lambda : null
  vpc_security_group_ids = length(local.list_of_subnets_to_attach_lambda) > 0 ? [aws_security_group.lambda[0].id] : null
  attach_network_policy  = length(local.list_of_subnets_to_attach_lambda) > 0 ? true : false

  source_path = [
    {
      path             = "${path.module}/src"
      pip_requirements = true
      patterns         = ["!\\.terragrunt-source-manifest"]
    }
  ]

  environment_variables = {
    LOG_LEVEL     = var.log_level
    DRY_RUN       = var.dry_run
    PCA_ARN       = var.pca_arn_for_lambda_policy
    COMMON_NAME   = var.cert_common_name
    SANS          = var.cert_list_of_sans
    VALIDITY_DAYS = var.cert_validitiy_days
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid = "AccessSecret"

    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:PutSecretValue",
      "secretsmanager:UpdateSecretVersionStage",
    ]

    resources = [
      "${var.secret_arn_for_lambda_policy}"
    ]
  }

  statement {
    sid = "AccessPCA"

    actions = [
      "acm-pca:IssueCertificate",
      "acm-pca:GetCertificate",
      "acm-pca:RevokeCertificate"
    ]

    resources = [
      "${var.pca_arn_for_lambda_policy}"
    ]
  }
}

resource "aws_lambda_permission" "secretmanager" {
  action        = "lambda:InvokeFunction"
  function_name = module.lambda.lambda_function_name
  principal     = "secretsmanager.amazonaws.com"
}

data "aws_vpc" "attach_to_vpc" {
  count = var.attach_to_vpc_id != "" ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [var.attach_to_vpc_id]
  }
}

data "aws_subnets" "private_subnets" {
  count = var.attach_to_vpc_id != "" ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.attach_to_vpc[0].id]
  }
  filter {
    name   = "tag:Name"
    values = ["*private*"] # Filters for subnets where the Name tag contains "private"
  }
}

resource "aws_security_group" "lambda" {
  count = length(local.list_of_subnets_to_attach_lambda) > 0 ? 1 : 0

  name        = "${local.lambda_name}-sg"
  description = "${local.lambda_name}-security-group"
  vpc_id      = data.aws_vpc.attach_to_vpc[0].id
}

#this lambda will only be triggered by Secrets Manager, so we only allow all outbound traffic
resource "aws_vpc_security_group_egress_rule" "allow_all_outbound" {
  count = length(local.list_of_subnets_to_attach_lambda) > 0 ? 1 : 0

  security_group_id = aws_security_group.lambda[0].id
  ip_protocol       = "-1"
  cidr_ipv4         = "0.0.0.0/0"
  description       = "Allow all outbound traffic"
}

##############################
# Common
##############################
data "aws_partition" "current" {}
data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
