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