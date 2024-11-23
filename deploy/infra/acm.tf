# list-api.
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

# log-api.
resource "aws_acm_certificate" "log_api" {
  provider          = aws.us_east_1
  domain_name       = "log-api.${var.main_domain}"
  validation_method = "DNS"
}

resource "aws_route53_record" "log_api_validation" {
  for_each = {
    for dvo in aws_acm_certificate.log_api.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "log_api" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.log_api.arn
  validation_record_fqdns = [for record in aws_route53_record.log_api_validation : record.fqdn]
}

# list.
resource "aws_acm_certificate" "list" {
  provider          = aws.us_east_1
  domain_name       = "list.${var.main_domain}"
  validation_method = "DNS"
}

resource "aws_route53_record" "list_validation" {
  for_each = {
    for dvo in aws_acm_certificate.list.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "list" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.list.arn
  validation_record_fqdns = [for record in aws_route53_record.list_validation : record.fqdn]
}

# log.
resource "aws_acm_certificate" "log" {
  provider          = aws.us_east_1
  domain_name       = "log.${var.main_domain}"
  validation_method = "DNS"
}

resource "aws_route53_record" "log_validation" {
  for_each = {
    for dvo in aws_acm_certificate.log.domain_validation_options : dvo.domain_name => {
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

resource "aws_acm_certificate_validation" "log" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.log.arn
  validation_record_fqdns = [for record in aws_route53_record.log_validation : record.fqdn]
}