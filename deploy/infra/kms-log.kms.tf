# This key is used to sign entries sent to the trillian personality
# The public key is publicly advertised, so that log entries are also verifiable
resource "aws_kms_key" "kms-log" {
  description              = "KMS key used to sign leaves sent to the trillian personality."
  key_usage                = "SIGN_VERIFY"
  customer_master_key_spec = "ECC_NIST_P384"
  deletion_window_in_days  = 7
  is_enabled               = true
}

# Get the public key ID
data "aws_kms_public_key" "ecc_p384_public_key" {
  key_id = aws_kms_key.kms-log.id
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
