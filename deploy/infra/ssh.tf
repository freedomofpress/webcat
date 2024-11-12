
# Generate SSH key pair; it is useful to tie a new one to each TF execution
resource "tls_private_key" "ec2_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Upload public key to AWS EC2 Key Pair
resource "aws_key_pair" "ssh_key" {
  key_name   = "ec2_key_terraform"
  public_key = tls_private_key.ec2_key.public_key_openssh
}

# Save the private key locally with secure permissions
resource "local_file" "private_key" {
  content         = tls_private_key.ec2_key.private_key_pem
  filename        = "${path.module}/ec2_key.pem"
  file_permission = "0400"
}