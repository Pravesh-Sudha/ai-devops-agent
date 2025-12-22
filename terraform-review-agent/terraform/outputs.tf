output "alb_dns_name" {
  description = "The URL of the application: "
  value       = aws_lb.app_alb.dns_name
}
