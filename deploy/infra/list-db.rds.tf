# DB Subnet Group for the private subnet
resource "aws_db_subnet_group" "list_db_subnet_group" {
  name       = "list_db_subnet_group"
  subnet_ids = [aws_subnet.main_vpc_private_subnet_a.id, aws_subnet.main_vpc_private_subnet_b.id]
}

# RDS MySQL instance for the list
resource "aws_db_instance" "list-db" {
  identifier              = "list-db"
  allocated_storage       = 5
  max_allocated_storage   = 100
  engine                  = "mysql"
  instance_class          = "db.t4g.micro"
  username                = "list-db"
  password                = random_password.mysql_password_list_db.result
  publicly_accessible     = false
  # TODO personalize and tighten groups
  vpc_security_group_ids  = [aws_security_group.log-db_sg.id]
  db_subnet_group_name    = aws_db_subnet_group.list_db_subnet_group.name
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