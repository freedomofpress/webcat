output "connect_command" {
  value = "ssh-add ec2_key.pem; ssh -A -i ${path.module}/ec2_key.pem ec2-user@${aws_instance.console.public_ip}"
}

output "mysql_connection_log_db" {
  value = "${var.mysql_user_log_db}:${random_password.mysql_password_log_db.result}@log-db.${var.main_domain}"
  sensitive = true
}

output "mysql_connection_list_db" {
  value = "${var.mysql_user_list_db}:${random_password.mysql_password_list_db.result}@log-db.${var.main_domain}"
  sensitive = true
}