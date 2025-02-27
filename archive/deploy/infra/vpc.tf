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

  lifecycle {
    ignore_changes = [subnet_ids]
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



resource "aws_route_table" "main_vpc_private_routing_table" {
  vpc_id = aws_vpc.main_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
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