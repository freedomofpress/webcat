
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