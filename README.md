# terraform-aws-secrets-manager-rotation-by-lambda-ses-smtp-credentials

A Terraform module creating an AWS Lambda function to enable creation of PCA certifcate and rotation
initiated by AWS Secrets Manager.

This Lambda function (supporting resources are created by this module) would be configured as the
rotation function for a given Secrets Manager secret configured for automatic rotation.

*Note - Initial/immediate rotation is performed as soon as the chosen Secret's Rotation
configuration is set to Enabled for automatic rotation in Secrets Manager
(or when the resource aws_secretsmanager_secret_rotation is applied to the secret)

If the function should be attached to a given vpc, provide a vpc id for the variable
attach_to_vpc_id.  A data source will try to find a list of subnet ids with the word *private* and
attach the function to those subnet ids.  If no subnets are found, or a specific set of subnet ids
are designed, a list of subnet ids can either be provided, or the function will not attach to the
provided vpc id.
Ensure the subnets selected within the vpc can reach the internet or has appropriate vpc endpoints
and configuration for private service access to PCA.

## Secret Structure

The AWS Secrets Manager secret is expected to contain the following JSON text strings with key-value
pairs structure to ensure proper validation prior to rotation:

```json
{
    "private_key":         "<PEM-encoded RSA private key>",
    "certificate":         "<PEM-encoded end-entity certificate>",
    "certificate_chain":   "<PEM-encoded CA chain (intermediates + root)>",
    "common_name":         "<CN used when issuing>",
    "sans":                ["<DNS SAN 1>", "<DNS SAN 2>", ...],
    "serial_number":       "<hex serial number of the issued certificate>",
    "issuer":              "<RFC 4514 distinguished name of the issuing CA>",
    "issued_at":           "<ISO-8601 UTC timestamp>",
    "expires_at":          "<ISO-8601 UTC timestamp>"
}
```

## AWS Lambda Function

AWS Lambda Function environment variables are populated based on Terraform variable values in this
module.

The function assumes when calculating the SMTP password that it is executing in the same region as
the intended SES SMTP endpoint for use.

The function follows structure from the Secrets Manager Rotation template and expects four steps.
Secret values should remain masked and attempts should be made to limit exposure in AWS logs.

### Summary of the four steps in the function

- createSecret - will create ... before storing in the secrets'
AWSPENDING label/stage.
- setSecret - attempts to ...
- testSecret - Once a sucessful setSecret completes, if set, will...
- finishSecret - If all prior steps succeed, moves the AWSCURRENT label/stage onto the AWSPENDING
label/stage in order for future builds/rotations to retrieve the proper value.

<!-- BEGIN TFDOCS -->
## Requirements

| Name | Version |
|------|---------|
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 5.74 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 5.74 |

## Resources

| Name | Type |
|------|------|
| [aws_caller_identity.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/caller_identity) | data source |
| [aws_iam_policy_document.lambda](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/iam_policy_document) | data source |
| [aws_partition.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/partition) | data source |
| [aws_region.current](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/region) | data source |
| [aws_subnets.private_subnets](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/subnets) | data source |
| [aws_vpc.attach_to_vpc](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/data-sources/vpc) | data source |

## Inputs

| Name | Description | Type | Default | Required |
|------|-------------|------|---------|:--------:|
| <a name="input_cert_common_name"></a> [cert\_common\_name](#input\_cert\_common\_name) | CN of certificate to request | `string` | n/a | yes |
| <a name="input_pca_arn_for_lambda_policy"></a> [pca\_arn\_for\_lambda\_policy](#input\_pca\_arn\_for\_lambda\_policy) | ARN of the PCA to request cert from | `string` | n/a | yes |
| <a name="input_project_name"></a> [project\_name](#input\_project\_name) | Project name to prefix resources with | `string` | n/a | yes |
| <a name="input_secret_arn_for_lambda_policy"></a> [secret\_arn\_for\_lambda\_policy](#input\_secret\_arn\_for\_lambda\_policy) | ARN of the secret to be configured for rotation, this is used to allow the lambda function to access only this secret | `string` | n/a | yes |
| <a name="input_attach_to_vpc_explicit_list_of_subnet_ids"></a> [attach\_to\_vpc\_explicit\_list\_of\_subnet\_ids](#input\_attach\_to\_vpc\_explicit\_list\_of\_subnet\_ids) | List of subnet IDs to attach lambda function to, if empty list provided, function will try to discover subnets with name containing private within the provided VPC id | `list(string)` | `[]` | no |
| <a name="input_attach_to_vpc_id"></a> [attach\_to\_vpc\_id](#input\_attach\_to\_vpc\_id) | VPC ID to attach lambda function to, if empty string provided, function won't be attached to any VPC | `string` | `""` | no |
| <a name="input_cert_list_of_sans"></a> [cert\_list\_of\_sans](#input\_cert\_list\_of\_sans) | ARN of the PCA to request cert from | `list(string)` | `[]` | no |
| <a name="input_cert_validitiy_days"></a> [cert\_validitiy\_days](#input\_cert\_validitiy\_days) | ARN of the PCA to request cert from | `number` | `365` | no |
| <a name="input_dry_run"></a> [dry\_run](#input\_dry\_run) | Boolean toggle to control the dry-run mode of the lambda function | `bool` | `true` | no |
| <a name="input_lambda"></a> [lambda](#input\_lambda) | Object of optional attributes passed on to the lambda module | <pre>object({<br/>    artifacts_dir                     = optional(string, "builds")<br/>    build_in_docker                   = optional(bool, false)<br/>    cloudwatch_logs_retention_in_days = optional(number, 365)<br/>    create_package                    = optional(bool, true)<br/>    ephemeral_storage_size            = optional(number)<br/>    ignore_source_code_hash           = optional(bool, true)<br/>    local_existing_package            = optional(string)<br/>    logging_log_group                 = optional(string, null)<br/>    memory_size                       = optional(number, 128)<br/>    recreate_missing_package          = optional(bool, false)<br/>    runtime                           = optional(string, "python3.12")<br/>    s3_bucket                         = optional(string)<br/>    s3_existing_package               = optional(map(string))<br/>    s3_prefix                         = optional(string)<br/>    store_on_s3                       = optional(bool, false)<br/>    timeout                           = optional(number, 300)<br/>    tracing_mode                      = optional(string, "PassThrough")<br/>    use_existing_cloudwatch_log_group = optional(bool, false)<br/>  })</pre> | `{}` | no |
| <a name="input_log_level"></a> [log\_level](#input\_log\_level) | Log level for lambda | `string` | `"INFO"` | no |
| <a name="input_tags"></a> [tags](#input\_tags) | Tags for resource | `map(string)` | `{}` | no |

## Outputs

No outputs.

<!-- END TFDOCS -->
