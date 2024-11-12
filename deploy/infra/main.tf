# Fetch the Route53 Zone using the main_domain
data "aws_route53_zone" "main_domain_zone" {
  name         = var.main_domain
  private_zone = false
}

# Random password for log-db
resource "random_password" "mysql_password_log_db" {
  length           = 32
  special          = true
  override_special = "_%"
}

# Random password for list-db
resource "random_password" "mysql_password_list_db" {
  length           = 32
  special          = true
  override_special = "_%"
}

# Random tree id for trillian
resource "random_integer" "trillian_log_id" {
  min = 0
  max = 4294967296
}

data "aws_availability_zones" "available" {}

# Fetch the latest AMi for this zone. AL2 is going to be deprecated, how to fetch AL3?
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}








