resource "aws_s3_bucket" "list" {
  bucket = "list.${var.main_domain}"
}

resource "aws_s3_object" "list_index" {
  bucket       = aws_s3_bucket.list.id
  key          = "index.html"
  content      = templatefile("../../web/list.html", {
    main_domain = var.main_domain
  })
  content_type = "text/html"
}

resource "aws_cloudfront_origin_access_control" "list_s3_access" {
  name       = "list-site-s3-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "list_site" {
  enabled             = true
  default_root_object = "index.html"

  origin {
    domain_name = aws_s3_bucket.list.bucket_regional_domain_name
    origin_id   = "s3-list-site"

    origin_access_control_id = aws_cloudfront_origin_access_control.list_s3_access.id
  }

  default_cache_behavior {
    target_origin_id       = "s3-list-site"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["GET", "HEAD"]
    cached_methods         = ["GET", "HEAD"]

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.list.arn
    ssl_support_method        = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  aliases = ["list.${var.main_domain}"]
}

resource "aws_s3_bucket_policy" "list_cloudfront_access" {
  bucket = aws_s3_bucket.list.id

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudfront.amazonaws.com"
      },
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::list.${var.main_domain}/*",
      "Condition": {
        "StringEquals": {
          "AWS:SourceArn": "${aws_cloudfront_distribution.list_site.arn}"
        }
      }
    }
  ]
}
EOF
}

resource "aws_route53_record" "list" {
  zone_id = data.aws_route53_zone.main_domain_zone.zone_id
  name    = "list.${var.main_domain}"
  type    = "A"

  alias {
    name                   = aws_cloudfront_distribution.list_site.domain_name
    zone_id                = aws_cloudfront_distribution.list_site.hosted_zone_id
    evaluate_target_health = false
  }
}