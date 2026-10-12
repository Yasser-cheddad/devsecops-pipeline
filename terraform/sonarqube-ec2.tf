# ============================================================
#  SonarQube – AWS EC2 t3.medium
#  PFE DevSecOps – EST Cybersécurité
# ============================================================

variable "admin_cidr_blocks" {
  description = "Allowed CIDR blocks for SonarQube and SSH administration access."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "instance_egress_cidr_blocks" {
  description = "Allowed CIDR blocks for SonarQube instance outbound traffic."
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

resource "aws_security_group" "sonarqube" {
  name        = "${var.project_name}-sonarqube-sg"
  description = "SonarQube EC2 access"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "SonarQube"
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_cidr_blocks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = var.instance_egress_cidr_blocks
  }

  tags = {
    Name    = "${var.project_name}-sonarqube-sg"
    Project = var.project_name
  }
}

resource "aws_iam_role" "sonarqube_ec2" {
  name = "${var.project_name}-sonarqube-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "sonarqube_ssm" {
  role       = aws_iam_role.sonarqube_ec2.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "sonarqube" {
  name = "${var.project_name}-sonarqube-profile"
  role = aws_iam_role.sonarqube_ec2.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

resource "aws_instance" "sonarqube" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.sonarqube.id]
  iam_instance_profile   = aws_iam_instance_profile.sonarqube.name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
    encrypted   = true
  }

  # Use templatefile to inject the password safely
  user_data = templatefile("${path.module}/sonarqube-init.sh", {
    sonar_password = var.sonar_admin_password
  })

  tags = {
    Name    = "${var.project_name}-sonarqube"
    Project = var.project_name
    Role    = "sonarqube"
  }
}

resource "aws_eip" "sonarqube" {
  instance = aws_instance.sonarqube.id
  domain   = "vpc"

  tags = {
    Name    = "${var.project_name}-sonarqube-eip"
    Project = var.project_name
  }
}

output "sonarqube_url" {
  description = "SonarQube public URL"
  value       = "http://${aws_eip.sonarqube.public_ip}:9000"
}

output "sonarqube_ip" {
  description = "SonarQube public IP"
  value       = aws_eip.sonarqube.public_ip
}
