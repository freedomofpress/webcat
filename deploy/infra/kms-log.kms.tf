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
