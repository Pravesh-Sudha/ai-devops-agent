resource "aws_secretsmanager_secret" "gemini_api_key" {
  name        = "gemini-api-key-1"
  description = "Gemini API key for Terraform AI Review Agent"
}

resource "aws_secretsmanager_secret_version" "gemini_api_key_value" {
  secret_id     = aws_secretsmanager_secret.gemini_api_key.id
  secret_string = jsonencode({
    GEMINI_API_KEY = var.gemini_api_key
  })
}
