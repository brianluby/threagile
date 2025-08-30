resource "aws_db_instance" "postgres" {
  identifier     = "webapp-db"
  engine         = "postgres"
  engine_version = "13.7"
  instance_class = "db.t3.micro"
  
  db_name  = "webapp"
  username = "dbadmin"
  password = "changeme"
}

resource "aws_s3_bucket" "assets" {
  bucket = "webapp-assets"
  
  tags = {
    Name = "Asset Storage"
  }
}
