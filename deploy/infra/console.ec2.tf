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