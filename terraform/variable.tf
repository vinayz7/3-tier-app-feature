variable "region" {
  description = "AWS region where resources will be deployed"
  default     = "us-west-1"
}
 
variable "db_username" {
  description = "Database username"
  default     = "admin"
}
 
variable "db_password" {
  description = "Database password"
  default     = "admin1234"
  sensitive   = true
}
 
variable "eks_admin_iam_arn" {
  description = "IAM ARN for EKS admin user"
  default     = "arn:aws:iam::619071307284:user/iamuser1"
}
 
 
 
