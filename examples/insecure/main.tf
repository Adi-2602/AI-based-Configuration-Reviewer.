provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "data" {
  bucket = "company-customer-data"
  acl    = "public-read"
}

resource "aws_db_instance" "main" {
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "changeme123!"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
  deletion_protection = false
}

resource "aws_iam_policy" "admin" {
  name = "too-broad"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }]
  })
}

resource "aws_instance" "app" {
  ami                         = "ami-12345678"
  instance_type               = "t3.micro"
  associate_public_ip_address = true
}
