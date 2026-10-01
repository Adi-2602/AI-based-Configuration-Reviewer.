terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

resource "aws_db_instance" "main" {
  engine                      = "postgres"
  instance_class              = "db.t3.micro"
  username                    = "app"
  manage_master_user_password = true
  publicly_accessible         = false
  storage_encrypted           = true
  deletion_protection         = true
  skip_final_snapshot         = false
}

resource "aws_instance" "app" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "required"
  }
}
