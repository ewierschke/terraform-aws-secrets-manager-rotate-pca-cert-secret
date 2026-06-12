variable "project_name" {
  description = "Project name to prefix resources with"
  type        = string
}

variable "dry_run" {
  description = "Boolean toggle to control the dry-run mode of the lambda function"
  type        = bool
  default     = true
}

#cloudwatch_logs_retention_in_days - security hub medium finding; default to address finding is 365 days
#tracing_mode - security hub low finding when Active tracing is not enabled, default is PassThrough
#use_existing_cloudwatch_log_group and logging_log_group - may be required for govcloud
variable "lambda" {
  description = "Object of optional attributes passed on to the lambda module"
  type = object({
    artifacts_dir                     = optional(string, "builds")
    build_in_docker                   = optional(bool, false)
    cloudwatch_logs_retention_in_days = optional(number, 365)
    create_package                    = optional(bool, true)
    ephemeral_storage_size            = optional(number)
    ignore_source_code_hash           = optional(bool, true)
    local_existing_package            = optional(string)
    logging_log_group                 = optional(string, null)
    memory_size                       = optional(number, 128)
    recreate_missing_package          = optional(bool, false)
    runtime                           = optional(string, "python3.12")
    s3_bucket                         = optional(string)
    s3_existing_package               = optional(map(string))
    s3_prefix                         = optional(string)
    store_on_s3                       = optional(bool, false)
    timeout                           = optional(number, 300)
    tracing_mode                      = optional(string, "PassThrough")
    use_existing_cloudwatch_log_group = optional(bool, false)
  })
  default = {}
}

variable "log_level" {
  description = "Log level for lambda"
  type        = string
  default     = "INFO"
  validation {
    condition     = contains(["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"], var.log_level)
    error_message = "Valid values for log level are (CRITICAL, ERROR, WARNING, INFO, DEBUG)."
  }
}

variable "tags" {
  description = "Tags for resource"
  type        = map(string)
  default     = {}
}

variable "secret_arn_for_lambda_policy" {
  description = "ARN of the secret to be configured for rotation, this is used to allow the lambda function to access only this secret"
  type        = string
}

variable "pca_arn_for_lambda_policy" {
  description = "ARN of the PCA to request cert from"
  type        = string
}

variable "cert_common_name" {
  description = "CN of certificate to request"
  type        = string
}

variable "cert_list_of_sans" {
  description = "ARN of the PCA to request cert from"
  type        = list(string)
  default     = [""]
}

variable "cert_validitiy_days" {
  description = "ARN of the PCA to request cert from"
  type        = number
  default     = 365
}

variable "attach_to_vpc_id" {
  description = "VPC ID to attach lambda function to, if empty string provided, function won't be attached to any VPC"
  type        = string
  default     = ""
}

variable "attach_to_vpc_explicit_list_of_subnet_ids" {
  description = "List of subnet IDs to attach lambda function to, if empty list provided, function will try to discover subnets with name containing private within the provided VPC id"
  type        = list(string)
  default     = []
}
