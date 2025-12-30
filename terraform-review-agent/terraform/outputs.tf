output "alb_dns_name" {
  description = "The URL of the application: "
  value       = aws_lb.app_alb.dns_name
}

output "acm_certificate_arn" {
  description = "ARN of the ACM certificate for mario.praveshsudha.com"
  value       = aws_acm_certificate.mario_cert.arn
}
