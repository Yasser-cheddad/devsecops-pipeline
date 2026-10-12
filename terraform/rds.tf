# ============================================================
#  RDS PostgreSQL – PFE DevSecOps
# ============================================================

# Security group for RDS (only accepts traffic from ECS tasks)
resource "aws_security_group" "rds" {
  name        = "${var.project_name}-rds-sg"
  description = "Allow PostgreSQL from ECS tasks only"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "PostgreSQL from ECS tasks"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ecs_tasks.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.project_name}-rds-sg"
    Project = var.project_name
  }
}

# RDS Subnet Group (uses private subnets)
resource "aws_db_subnet_group" "main" {
  name       = "${var.project_name}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name    = "${var.project_name}-db-subnet-group"
    Project = var.project_name
  }
  lifecycle {
    ignore_changes = [subnet_ids]
  }
}
 

# RDS PostgreSQL Instance (t3.micro = free tier eligible)
resource "aws_db_instance" "main" {
  identifier        = "${var.project_name}-db"
  engine            = "postgres"
  engine_version    = "15"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"

  db_name  = "devsecops"
  username = "dbadmin"
  password = var.db_password

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]

  # Security best practices (Checkov compliant)
  publicly_accessible     = false
  skip_final_snapshot     = true   # set false in real production
  deletion_protection     = false  # set true in real production
  storage_encrypted       = true
  backup_retention_period = 7
  multi_az                = false  # true in production

  tags = {
    Name        = "${var.project_name}-db"
    Project     = var.project_name
    Environment = var.environment
  }
   lifecycle {
    ignore_changes = [vpc_security_group_ids, engine_version, password, db_subnet_group_name]
  }
}
