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

  ingress {
    description     = "Trillian API"
    from_port       = 8090
    to_port         = 8090
    protocol        = "tcp"
    # can probably be changed to var.vpc_range or directly aws_instance.console.private_ip
    cidr_blocks = [aws_subnet.main_vpc_private_subnet_a.cidr_block]
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