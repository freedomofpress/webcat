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
  username                = "log-db"
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
