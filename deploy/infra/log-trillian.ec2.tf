
resource "aws_instance" "log_trillian" {
  ami               = data.aws_ami.amazon_linux_2.id
  instance_type     = "t3.small"
  availability_zone = data.aws_availability_zones.available.names[0]
  key_name          = aws_key_pair.ssh_key.key_name
  tenancy           = "default"
  subnet_id         = aws_subnet.main_vpc_private_subnet_a.id
  vpc_security_group_ids = [aws_security_group.private_sg.id]

  # This inherently waits for the rds to exist as well
  depends_on = [ aws_route53_record.log-db ]

  # TODO in prod disable SSH and remove metadata
  # would be nice but: https://github.com/hashicorp/terraform-provider-aws/issues/29829
  #metadata_options {
  #  http_endpoint               = "disabled"
  #}

  user_data = templatefile("${path.module}/trillian_setup.sh.tpl", {
    host              = "log-db.${var.main_domain}"
    root_user         = var.mysql_user_log_db
    root_password     = random_password.mysql_password_log_db.result
    trillian_user     = "trillian"
    trillian_password = random_password.mysql_password_log_db_trillian.result
    trillian_db       = "trillian"
  })

  tags = {
    "name" = "log_trillian"
  }
}

# Debug
#resource "local_file" "rendered_trillian_setup" {
#  content  = templatefile("${path.module}/trillian_setup.sh.tpl", {
#    host              = "log-db.${var.main_domain}"
#    root_user         = var.mysql_user_log_db
#    root_password     = random_password.mysql_password_log_db.result
#    trillian_user     = "trillian"
#    trillian_password = random_password.mysql_password_log_db_trillian.result
#    trillian_db       = "trillian"
#  })
#  filename = "${path.module}/rendered_trillian_setup.sh"
#}

resource "aws_route53_record" "log_trillian" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "log-trillian.${var.main_domain}"
  type    = "A"
  ttl     = 300
  records = [aws_instance.log_trillian.private_ip]
}