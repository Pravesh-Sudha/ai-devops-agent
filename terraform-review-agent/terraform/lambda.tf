resource "aws_lambda_function" "terraform_ai_reviewer" {
  function_name = "terraform-ai-review-agent"
  filename      = "lambda.zip"
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  timeout       = 60

  depends_on = [
    aws_secretsmanager_secret_version.gemini_api_key_value,
    aws_iam_role_policy_attachment.lambda_secrets_attach,
    aws_iam_role_policy_attachment.basic_logs
  ]
}
