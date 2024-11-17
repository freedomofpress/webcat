resource "aws_lambda_function" "log_api" {
  function_name = "log_api"
  handler       = "api.lambda_handler"
  runtime       = "python3.11"
  role          = aws_iam_role.lambda_role.arn
  filename      = "../../dist/transparency-lambda.zip"
  timeout       = 30

  depends_on = [aws_db_instance.log-db, aws_instance.log_trillian, aws_route53_record.log_trillian]

  vpc_config {
    subnet_ids         = [aws_subnet.main_vpc_private_subnet_a.id]
    security_group_ids = [aws_security_group.private_sg.id]
  }

  environment {
    variables = {
      DB_HOST         = "log-db.${var.main_domain}"
      DB_PORT         = 3306
      # TODO do not run this as the root mysql user, rather create another one and drop privs
      DB_USER         = var.mysql_user_log_db
      DB_PASSWORD     = random_password.mysql_password_log_db.result
      DB_NAME         = "log_api"
      TRILLIAN_HOST   = "log-trillian.${var.main_domain}"
      TRILLIAN_PORT   = 8090
      PUBLIC_KEY      = data.aws_kms_public_key.ecc_p384_public_key.public_key_pem
    }
  }
}

# DEBUG
resource "aws_lambda_function_url" "log_api_url" {
  function_name = aws_lambda_function.log_api.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST"]
  }
}

output "lambda_function_url" {
  value = aws_lambda_function_url.log_api_url.function_url
  description = "The URL endpoint for the Flask Lambda function"
}
