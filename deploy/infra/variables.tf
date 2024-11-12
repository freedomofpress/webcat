provider "aws" {
  region = var.region
}

# Main domain, this TF assumes it is already a Route53 Zone
variable "main_domain" {
  description = "The main domain for Route 53"
  type        = string
  default     = "transparency.cat"
}

variable "region" {
  description = "AWS region for resources"
  type        = string
  default     = "eu-north-1"
}

variable "vpc_range" {
  # /16 is the biggest max a VPC supports
  description = "Either 10.0.0.0/16, 172.16.0.0/16, or 192.168.0.0/16"
  type        = string
  default     = "172.16.0.0/16"
}

