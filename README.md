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
| <a name="requirement_terraform"></a> [terraform](#requirement\_terraform) | >= 1.5.7 |
| <a name="requirement_aws"></a> [aws](#requirement\_aws) | >= 6.0 |

## Providers

| Name | Version |
|------|---------|
| <a name="provider_aws"></a> [aws](#provider\_aws) | >= 6.0 |

## Resources



## Outputs

No outputs.

<!-- END TFDOCS -->
