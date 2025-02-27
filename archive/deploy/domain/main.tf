provider "aws" {
  region = "eu-north-1"
}

variable "main_domain" {
  description = "The main domain for the webcat infrastructure."
  type        = string
  default     = "transparency.cat"
}

# Create Route 53 Hosted Zone
resource "aws_route53_zone" "main_domain" {
  name = var.main_domain
}

# Output the Route 53 nameservers to be used for domain delegation
output "nameservers" {
  description = "Route 53 nameservers to delegate to."
  value       = aws_route53_zone.main_domain.name_servers
}
