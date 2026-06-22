resource "aws_s3_bucket" "evidence_vault" {
  bucket        = "${local.name_prefix}-evidence-vault-${local.suffix}"
  force_destroy = false

  object_lock_enabled = true

  tags = {
    Purpose = "GRCEvidenceVault"
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 90
    }
  }
}

output "evidence_vault_bucket" {
  value = aws_s3_bucket.evidence_vault.id
}
