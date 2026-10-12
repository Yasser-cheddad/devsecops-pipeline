variable "aws_region" {
  description = "AWS region"
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Nom du projet"
  default     = "pfe-devsecops"
}

variable "db_password" {
  description = "Mot de passe RDS PostgreSQL"
  sensitive   = true
}

variable "app_image" {
  description = "Image Docker à déployer sur ECS"
  default     = "bkimminich/juice-shop:latest"
}

variable "environment" {
  description = "Environnement de déploiement"
  default     = "staging"
}
variable "sonar_admin_password" {
  description = "Mot de passe admin SonarQube"
  sensitive   = true
  default     = "SonarPfe2026!"
}
