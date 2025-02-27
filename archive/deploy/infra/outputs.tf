output "connect_command" {
  value = "ssh-add ec2_key.pem; ssh -A -i ${path.module}/ec2_key.pem ec2-user@${aws_instance.console.public_ip}"
}

output "mysql_connection_log_db" {
  value = "${var.mysql_user_log_db}:${random_password.mysql_password_log_db.result}@log-db.${var.main_domain}"
  sensitive = true
}

output "mysql_connection_list_db" {
  value = "${var.mysql_user_list_db}:${random_password.mysql_password_list_db.result}@list-db.${var.main_domain}"
  sensitive = true
}

# Output the public key in PEM format
output "ecc_p384_public_key" {
  value       = data.aws_kms_public_key.ecc_p384_public_key.public_key
  description = "The public key of the ECC P-384 KMS key in PEM format"
}

# Output the KMS Key ID
output "ecc_p384_key_id" {
  value       = aws_kms_key.kms-log.id
  description = "The ID of the ECC P-384 KMS key"
}