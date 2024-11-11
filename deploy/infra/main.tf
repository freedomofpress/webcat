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

data "aws_availability_zones" "available" {}

# fetch the latest AMi for this zone. AL2 is going to be deprecated, how to fetch AL3?
data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Generate SSH key pair; it is useful to tie a new one to each TF execution
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Upload public key to AWS EC2 Key Pair
resource "aws_key_pair" "ssh_key" {
  key_name   = "ec2_key_terraform"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

# Save the private key locally with secure permissions
resource "local_file" "private_key" {
  content         = tls_private_key.ec2_key.private_key_pem
  filename        = "${path.module}/ec2_key.pem"
  file_permission = "0400"
}

# VPC, 
resource "aws_vpc" "main_vpc" {
  cidr_block           = var.vpc_range
  instance_tenancy     = "default"
  #enable_dns_support   = true
  #enable_dns_hostnames = true

  tags = {
    Name = "main_vpc"
  }
}

resource "aws_internet_gateway" "main_vpc_gateway" {
  vpc_id = aws_vpc.main_vpc.id

  tags = {
    Name = "main_vpc_gateway"
  }
}

resource "aws_subnet" "main_vpc_public_subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.main_vpc.cidr_block, 8, 1)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "main_vpc_public_subnet_a"
  }
}

resource "aws_network_acl" "public_subnet_acl" {
vpc_id = aws_vpc.main_vpc.id
subnet_ids = [aws_subnet.main_vpc_public_subnet_a.id]

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    "name" = "public_subnet_acl"
  }
}

resource "aws_network_acl_association" "public_subnet_acl_association_a" {
  network_acl_id = aws_network_acl.public_subnet_acl.id
  subnet_id      = aws_subnet.main_vpc_public_subnet_a.id
}

resource "aws_route_table" "main_vpc_public_routing_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main_vpc_gateway.id
  }

  tags = {
    Name = "main_vpc_public_routing_table"
  }
}

resource "aws_route_table_association" "public_subnet_rt_association" {
  subnet_id      = aws_subnet.main_vpc_public_subnet_a.id
  route_table_id = aws_route_table.main_vpc_public_routing_table.id
}

resource "aws_security_group" "remote_ssh_sg" {
  vpc_id      = aws_vpc.main_vpc.id
  description = "SSH"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "console" {
  ami               = data.aws_ami.amazon_linux_2.id
  instance_type     = "t3.micro"
  availability_zone = data.aws_availability_zones.available.names[0]
  key_name          = aws_key_pair.ssh_key.key_name
  tenancy           = "default"
  subnet_id         = aws_subnet.main_vpc_public_subnet_a.id
  vpc_security_group_ids = [aws_security_group.remote_ssh_sg.id]
}

resource "aws_route53_record" "console" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "console.${var.main_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.console.public_ip]
}


resource "aws_eip" "eip_for_nat" {
}

resource "aws_nat_gateway" "nat_gw" {
  subnet_id         = aws_subnet.main_vpc_public_subnet_a.id
  connectivity_type = "public"
  allocation_id     = aws_eip.eip_for_nat.id

  tags = {
    "Name" = "nat_gw"
  }
}

# Private subnet 1
resource "aws_subnet" "main_vpc_private_subnet_a" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.main_vpc.cidr_block, 8, 10)
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = false

  tags = {
    Name = "main_vpc_private_subnet_a"
  }
}

# Private subnet 2, as we need subnets in 2 availability zones for RDS
resource "aws_subnet" "main_vpc_private_subnet_b" {
  vpc_id                  = aws_vpc.main_vpc.id
  cidr_block              = cidrsubnet(aws_vpc.main_vpc.cidr_block, 8, 20)
  availability_zone       = data.aws_availability_zones.available.names[1]
  map_public_ip_on_launch = false

  tags = {
    Name = "main_vpc_private_subnet_a"
  }
}

resource "aws_network_acl" "private_subnet_acl" {
vpc_id = aws_vpc.main_vpc.id
subnet_ids = [aws_subnet.main_vpc_private_subnet_a.id]

  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  egress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = {
    "name" = "private_subnet_acl"
  }
}

resource "aws_network_acl_association" "private_subnet_acl_association_a" {
  network_acl_id = aws_network_acl.private_subnet_acl.id
  subnet_id      = aws_subnet.main_vpc_private_subnet_a.id
}

resource "aws_network_acl_association" "private_subnet_acl_association_b" {
  network_acl_id = aws_network_acl.private_subnet_acl.id
  subnet_id      = aws_subnet.main_vpc_private_subnet_b.id
}

resource "aws_security_group" "private_sg" {
  name        = "private_sg"
  description = "Security group for private subnet instances."
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description     = "SSH"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    # can probably be changed to var.vpc_range or directly aws_instance.console.private_ip
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All"
    from_port   = 0
    to_port     = 0
    protocol    = -1
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    "name" = "private_sg"
  }
}

resource "aws_route_table" "main_vpc_private_routing_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_nat_gateway.nat_gw.id
  }

  tags = {
    Name = "main_vpc_private_routing_table"
  }
}

resource "aws_route_table_association" "private_subnet_a_rt_association" {
  subnet_id      = aws_subnet.main_vpc_private_subnet_a.id
  route_table_id = aws_route_table.main_vpc_private_routing_table.id
}

resource "aws_route_table_association" "private_subnet_b_rt_association" {
  subnet_id      = aws_subnet.main_vpc_private_subnet_b.id
  route_table_id = aws_route_table.main_vpc_private_routing_table.id
}

resource "aws_instance" "log-trillian" {
  ami               = data.aws_ami.amazon_linux_2.id
  instance_type     = "t3.micro"
  availability_zone = data.aws_availability_zones.available.names[0]
  key_name          = aws_key_pair.ssh_key.key_name
  tenancy           = "default"
  subnet_id         = aws_subnet.main_vpc_private_subnet_a.id
  vpc_security_group_ids = [aws_security_group.private_sg.id]

  tags = {
    "name" = "log-trillian"
  }
}

resource "aws_route53_record" "log-trillian" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "log-trillian.${var.main_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.log-trillian.private_ip]
}

resource "aws_security_group" "log-db_sg" {
  name        = "${var.main_domain}-log-db_sg"
  description = "Allow MySQL access from EC2 instance in private subnet"
  vpc_id      = aws_vpc.main_vpc.id

  ingress {
    description = "MySQL access from EC2"
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    # TODO: restrict more?
    cidr_blocks = [aws_subnet.main_vpc_private_subnet_a.cidr_block, aws_subnet.main_vpc_private_subnet_b.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# DB Subnet Group for the private subnet
resource "aws_db_subnet_group" "log_db_subnet_group" {
  name       = "log_db_subnet_group"
  subnet_ids = [aws_subnet.main_vpc_private_subnet_a.id, aws_subnet.main_vpc_private_subnet_b.id]
}

# RDS MySQL for trillian and the personality
resource "aws_db_instance" "log-db" {
  identifier              = "log-db"
  allocated_storage       = 5
  max_allocated_storage   = 100
  engine                  = "mysql"
  instance_class          = "db.t4g.micro"        # Cheapest instance type
  username                = "admin"
  password                = random_password.mysql_password_log_db.result
  publicly_accessible     = false
  vpc_security_group_ids  = [aws_security_group.log-db_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.log_db_subnet_group.name
  # TODO: in prod this should be false
  skip_final_snapshot     = true
}

# Route 53 record log-db
resource "aws_route53_record" "log-db" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "log-db.${var.main_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_db_instance.log-db.address]
}

# RDS MySQL instance for the list
resource "aws_db_instance" "list-db" {
  identifier              = "list-db"
  allocated_storage       = 5
  max_allocated_storage   = 100
  engine                  = "mysql"
  instance_class          = "db.t4g.micro"
  username                = "admin"
  password                = random_password.mysql_password_list_db.result
  publicly_accessible     = false
  # TODO personalize and tighten groups
  vpc_security_group_ids  = [aws_security_group.log-db_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.log_db_subnet_group.name
  # TODO: in prod this should be false
  skip_final_snapshot     = true

}

# Route 53 record for list-db
resource "aws_route53_record" "list-db" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "list-db.${var.main_domain}"
  type    = "CNAME"
  ttl     = 300
  records = [aws_db_instance.list-db.address]
}

output "connect_command" {
  value = "ssh-add ec2_key.pem; ssh -A -i ${path.module}/ec2_key.pem ec2-user@${aws_instance.console.public_ip}"
}

output "mysql_password_log_db" {
  value = random_password.mysql_password_log_db.result
  sensitive = true
}

output "mysql_password_list_db" {
  value = random_password.mysql_password_list_db.result
  sensitive = true
}