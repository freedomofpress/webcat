resource "aws_iam_role" "lambda_role" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  })
}

# Attach a policy to allow Lambda to write logs to CloudWatch
resource "aws_iam_role_policy_attachment" "lambda_logging" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_lambda_function" "list_api" {
  function_name = "list_api"
  handler       = "main.lambda_handler"
  runtime       = "python3.12"
  role          = aws_iam_role.lambda_role.arn
  filename      = "../../dist/submission-lambda.zip"
  timeout       = 30

  depends_on = [aws_db_instance.list-db]

  vpc_config {
    subnet_ids         = [aws_subnet.main_vpc_private_subnet_a.id]
    security_group_ids = [aws_security_group.private_sg.id]
  }

  environment {
    variables = {
      DB_HOST         = "list-db.${var.main_domain}"
      DB_PORT         = 3306
      # TODO do not run this as the root mysql user, rather create another one and drop privs
      DB_USER    = var.mysql_user_list_db
      DB_PASSWORD = random_password.mysql_password_list_db.result
      #DB_USER         = "list_api"
      #DB_PASSWORD     = ${}
      DB_NAME         = "list_api"
    }
  }
}

# DEBUG
#resource "aws_lambda_function_url" "list_api_url" {
#  function_name = aws_lambda_function.list_api.function_name
#  authorization_type = "NONE"

#  cors {
#    allow_origins = ["*"]
#    allow_methods = ["GET", "POST"]
#  }
#}

#output "lambda_function_url" {
#  value = aws_lambda_function_url.list_api_url.function_url
#  description = "The URL endpoint for the Flask Lambda function"
#}

resource "aws_api_gateway_stage" "prod" {
  deployment_id = aws_api_gateway_deployment.list_api_deployment.id
  rest_api_id   = aws_api_gateway_rest_api.list_api.id
  stage_name    = "prod"
}

resource "aws_api_gateway_rest_api" "list_api" {
  name        = "list_api"
  description = "API Gateway for the list-api endpoint"
}

resource "aws_api_gateway_resource" "submission" {
  rest_api_id = aws_api_gateway_rest_api.list_api.id
  parent_id   = aws_api_gateway_rest_api.list_api.root_resource_id
  path_part   = "submission"
}

resource "aws_api_gateway_resource" "submission_id" {
  rest_api_id = aws_api_gateway_rest_api.list_api.id
  parent_id   = aws_api_gateway_resource.submission.id
  path_part   = "{id}"
}

# POST and GET for /submission
resource "aws_api_gateway_method" "submission_post" {
  rest_api_id   = aws_api_gateway_rest_api.list_api.id
  resource_id   = aws_api_gateway_resource.submission.id
  http_method   = "POST"
  authorization = "NONE"
}

resource "aws_api_gateway_method" "submission_get" {
  rest_api_id   = aws_api_gateway_rest_api.list_api.id
  resource_id   = aws_api_gateway_resource.submission.id
  http_method   = "GET"
  authorization = "NONE"
}

# GET for /submission/{id}
resource "aws_api_gateway_method" "submission_id_get" {
  rest_api_id   = aws_api_gateway_rest_api.list_api.id
  resource_id   = aws_api_gateway_resource.submission_id.id
  http_method   = "GET"
  authorization = "NONE"
}

# Lambda Integration for /submission POST
resource "aws_api_gateway_integration" "submission_post_integration" {
  rest_api_id             = aws_api_gateway_rest_api.list_api.id
  resource_id             = aws_api_gateway_resource.submission.id
  http_method             = aws_api_gateway_method.submission_post.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.list_api.invoke_arn
}

# Lambda Integration for /submission GET
resource "aws_api_gateway_integration" "submission_get_integration" {
  rest_api_id             = aws_api_gateway_rest_api.list_api.id
  resource_id             = aws_api_gateway_resource.submission.id
  http_method             = aws_api_gateway_method.submission_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.list_api.invoke_arn
}

# Lambda Integration for /submission/{id} GET
resource "aws_api_gateway_integration" "submission_id_get_integration" {
  rest_api_id             = aws_api_gateway_rest_api.list_api.id
  resource_id             = aws_api_gateway_resource.submission_id.id
  http_method             = aws_api_gateway_method.submission_id_get.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.list_api.invoke_arn
}

resource "aws_api_gateway_deployment" "list_api_deployment" {
  depends_on = [
    aws_api_gateway_integration.submission_id_get_integration,
    aws_api_gateway_integration.submission_get_integration,
    aws_api_gateway_integration.submission_post_integration
  ]
  rest_api_id = aws_api_gateway_rest_api.list_api.id
}

resource "aws_lambda_permission" "allow_api_gateway" {
  statement_id  = "AllowAPIGatewayInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.list_api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_api_gateway_rest_api.list_api.execution_arn}/*/*"
}

resource "aws_acm_certificate" "list_api" {
  provider          = aws.us_east_1
  domain_name       = "list-api.${var.main_domain}"
  validation_method = "DNS"
}

resource "aws_route53_record" "list_api_validation" {
  for_each = {
    for dvo in aws_acm_certificate.list_api.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = data.aws_route53_zone.main_domain_zone.zone_id
}

resource "aws_acm_certificate_validation" "list_api" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.list_api.arn
  validation_record_fqdns = [for record in aws_route53_record.list_api_validation : record.fqdn]
}

resource "aws_api_gateway_domain_name" "list_api" {
  domain_name     = "list-api.${var.main_domain}"
  certificate_arn = aws_acm_certificate.list_api.arn
  depends_on = [ aws_acm_certificate_validation.list_api, aws_acm_certificate.list_api ]
}

resource "aws_api_gateway_base_path_mapping" "api_mapping" {
  api_id      = aws_api_gateway_rest_api.list_api.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  domain_name = aws_api_gateway_domain_name.list_api.domain_name
  base_path   = "" 
}

resource "aws_route53_record" "list_api" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "list-api.${data.aws_route53_zone.main_domain_zone.name}"
  type    = "A"

  alias {
    name                   = aws_api_gateway_domain_name.list_api.cloudfront_domain_name
    zone_id                = aws_api_gateway_domain_name.list_api.cloudfront_zone_id
    evaluate_target_health = false
  }
}


output "api_url" {
  value = "${aws_api_gateway_deployment.list_api_deployment.invoke_url}"
  description = "The API Gateway endpoint for the /submission Lambda function"
}