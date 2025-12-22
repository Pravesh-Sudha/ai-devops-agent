variable "project_name" {
  type        = string
  default     = "mario-game"
  description = "Name of the project"
}

variable "gemini_api_key" {
  description = "Gemini API Key"
  type        = string
  sensitive   = true
}
