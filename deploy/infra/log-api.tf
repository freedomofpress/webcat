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
#resource "aws_lambda_function_url" "log_api_url" {
#  function_name = aws_lambda_function.log_api.function_name
#  authorization_type = "NONE"

#  cors {
#    allow_origins = ["*"]
#    allow_methods = ["GET", "POST"]
#  }
#}

#output "lambda_function_url" {
#  value = aws_lambda_function_url.log_api_url.function_url
#  description = "The URL endpoint for the Flask Lambda function"
#}

resource "aws_api_gateway_stage" "prod_log_api" {
  deployment_id = aws_api_gateway_deployment.log_api.id
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  stage_name    = "prod_log"
}

# Define the API Gateway REST API
resource "aws_api_gateway_rest_api" "log_api" {
  name        = "log_api"
  description = "API Gateway for the log-api endpoint"
}

# Define the "/v1" resource
resource "aws_api_gateway_resource" "v1" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_rest_api.log_api.root_resource_id
  path_part   = "v1"
}

# Queue submission - /v1/queue_leaf (POST)
resource "aws_api_gateway_resource" "queue_leaf" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "queue_leaf"
}

resource "aws_api_gateway_method" "queue_leaf_post" {
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  resource_id   = aws_api_gateway_resource.queue_leaf.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "queue_leaf_integration" {
  rest_api_id             = aws_api_gateway_rest_api.log_api.id
  resource_id             = aws_api_gateway_resource.queue_leaf.id
  http_method             = aws_api_gateway_method.queue_leaf_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.log_api.invoke_arn
}

# Proof - /v1/proof/{lookup_method}/{param} (GET)
resource "aws_api_gateway_resource" "proof" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "proof"
}

resource "aws_api_gateway_resource" "proof_lookup_method" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.proof.id
  path_part   = "{lookup_method}"
}

resource "aws_api_gateway_resource" "proof_param" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.proof_lookup_method.id
  path_part   = "{param}"
}

resource "aws_api_gateway_method" "proof_get" {
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  resource_id   = aws_api_gateway_resource.proof_param.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "proof_integration" {
  rest_api_id             = aws_api_gateway_rest_api.log_api.id
  resource_id             = aws_api_gateway_resource.proof_param.id
  http_method             = aws_api_gateway_method.proof_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.log_api.invoke_arn
}

# Leaf - /v1/leaf/{lookup_method}/{param} (GET)
resource "aws_api_gateway_resource" "leaf" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "leaf"
}

resource "aws_api_gateway_resource" "leaf_lookup_method" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.leaf.id
  path_part   = "{lookup_method}"
}

resource "aws_api_gateway_resource" "leaf_param" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.leaf_lookup_method.id
  path_part   = "{param}"
}

resource "aws_api_gateway_method" "leaf_get" {
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  resource_id   = aws_api_gateway_resource.leaf_param.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "leaf_integration" {
  rest_api_id             = aws_api_gateway_rest_api.log_api.id
  resource_id             = aws_api_gateway_resource.leaf_param.id
  http_method             = aws_api_gateway_method.leaf_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.log_api.invoke_arn
}

# Root - /v1/root (GET)
resource "aws_api_gateway_resource" "root_resource" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "root"
}

resource "aws_api_gateway_method" "root_get" {
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  resource_id   = aws_api_gateway_resource.root_resource.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "root_integration" {
  rest_api_id             = aws_api_gateway_rest_api.log_api.id
  resource_id             = aws_api_gateway_resource.root_resource.id
  http_method             = aws_api_gateway_method.root_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.log_api.invoke_arn
}

# Info - /v1/info (GET)
resource "aws_api_gateway_resource" "info" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id
  parent_id   = aws_api_gateway_resource.v1.id
  path_part   = "info"
}

resource "aws_api_gateway_method" "info_get" {
  rest_api_id   = aws_api_gateway_rest_api.log_api.id
  resource_id   = aws_api_gateway_resource.info.id
  http_method   = "GET"
  authorization = "NONE"
}

resource "aws_api_gateway_integration" "info_integration" {
  rest_api_id             = aws_api_gateway_rest_api.log_api.id
  resource_id             = aws_api_gateway_resource.info.id
  http_method             = aws_api_gateway_method.info_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.log_api.invoke_arn
}

# Lambda Permission for API Gateway to invoke it
resource "aws_lambda_permission" "log_api_permission" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.log_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.log_api.execution_arn}/*/*"
}

# Deployment for API Gateway
resource "aws_api_gateway_deployment" "log_api" {
  rest_api_id = aws_api_gateway_rest_api.log_api.id

  depends_on = [
    aws_api_gateway_integration.queue_leaf_integration,
    aws_api_gateway_integration.proof_integration,
    aws_api_gateway_integration.leaf_integration,
    aws_api_gateway_integration.root_integration,
    aws_api_gateway_integration.info_integration,
  ]
}

resource "aws_api_gateway_domain_name" "log_api" {
  domain_name     = "log-api.${var.main_domain}"
  certificate_arn = aws_acm_certificate.log_api.arn
  depends_on = [ aws_acm_certificate_validation.log_api, aws_acm_certificate.log_api ]
}

resource "aws_api_gateway_base_path_mapping" "log_api_mapping" {
  api_id      = aws_api_gateway_rest_api.log_api.id
  stage_name  = aws_api_gateway_stage.prod_log_api.stage_name
  domain_name = aws_api_gateway_domain_name.log_api.domain_name
  base_path   = "" 
}

resource "aws_route53_record" "log_api" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "log-api.${data.aws_route53_zone.main_domain_zone.name}"
  type    = "A"

  alias {
    name                   = aws_api_gateway_domain_name.log_api.cloudfront_domain_name
    zone_id                = aws_api_gateway_domain_name.log_api.cloudfront_zone_id
    evaluate_target_health = false
  }
}

# Output the API endpoint URL
output "log_api_url" {
  value       = "${aws_api_gateway_deployment.log_api.invoke_url}"
  description = "The URL endpoint for the log-api API"
}
