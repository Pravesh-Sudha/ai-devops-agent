terraform {
  backend "s3" {
    bucket       = "pravesh-terraform-mario-state"
    key          = "ecs/serverless/terraform.tfstate"
    region       = "us-east-1"
    use_lockfile = true
    encrypt      = true
  }
}