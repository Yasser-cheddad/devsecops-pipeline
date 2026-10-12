# ============================================================
#  Outputs – PFE DevSecOps
#  Ces valeurs sont utilisées par le pipeline GitLab CI
# ============================================================

output "app_url" {
  description = "URL publique de l'application (Load Balancer)"
  value       = "http://${aws_lb.main.dns_name}"
}

output "alb_dns_name" {
  description = "DNS name du Load Balancer"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "URL du registry ECR pour push les images Docker"
  value       = aws_ecr_repository.app.repository_url
}

output "ecs_cluster_name" {
  description = "Nom du cluster ECS"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "Nom du service ECS"
  value       = aws_ecs_service.app.name
}

output "rds_endpoint" {
  description = "Endpoint de la base de données RDS"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "vpc_id" {
  description = "ID du VPC"
  value       = aws_vpc.main.id
}
