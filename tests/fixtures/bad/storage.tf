resource "aws_s3_bucket" "data" {
  bucket = "demo-data-bucket-fixture"
}

resource "aws_s3_bucket" "logs" {
  bucket = "demo-logs-bucket-fixture"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_db_instance" "main" {
  identifier                  = "demo-db"
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  allocated_storage           = 20
  username                    = "dbadmin"
  manage_master_user_password = true
  skip_final_snapshot         = true
  storage_encrypted           = false
}

resource "aws_ebs_volume" "scratch" {
  availability_zone = "us-east-1a"
  size              = 1
}

resource "aws_s3_bucket_logging" "data" {
  bucket        = aws_s3_bucket.data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "data/"
}
