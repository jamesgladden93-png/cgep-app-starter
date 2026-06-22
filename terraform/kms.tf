resource "aws_kms_key" "phi" {
  description         = "Acme Health PHI Encryption Key"
  enable_key_rotation = true

  tags = {
    Purpose = "PHI"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/acme-health-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}