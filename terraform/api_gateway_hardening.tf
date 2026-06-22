resource "aws_cloudwatch_log_group" "apigw" {
  name              = "/aws/apigateway/acme-health-intake"
  retention_in_days = 90
}