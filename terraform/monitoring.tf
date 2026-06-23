######################################################################
# Monitoring & Detection — CMMC L2 AU.L2-3.3.1, SI.L2-3.14.6
# CloudWatch alarms, EventBridge rules, and SNS topic for real-time
# detection of compliance drift and security events.
######################################################################

resource "aws_sns_topic" "alerts" {
  name              = "${local.name_prefix}-alerts-${local.suffix}"
  kms_master_key_id = aws_kms_key.phi.id

  tags = {
    Purpose = "SecurityAlerts"
  }
}

######################################################################
# CloudWatch Metric Filters + Alarms (CIS / CMMC AU.L2-3.3.1)
######################################################################

resource "aws_cloudwatch_log_metric_filter" "root_login" {
  name           = "${local.name_prefix}-root-login-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootLoginCount"
    namespace = "AcmeHealth/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_login" {
  alarm_name          = "${local.name_prefix}-root-login-alarm-${local.suffix}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootLoginCount"
  namespace           = "AcmeHealth/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CMMC AU.L2-3.3.1: Alert on root account usage"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Purpose = "ComplianceMonitoring"
  }
}

resource "aws_cloudwatch_log_metric_filter" "kms_key_deletion" {
  name           = "${local.name_prefix}-kms-deletion-${local.suffix}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.eventSource = \"kms.amazonaws.com\" && ($.eventName = \"ScheduleKeyDeletion\" || $.eventName = \"DisableKey\") }"

  metric_transformation {
    name      = "KMSKeyDeletionCount"
    namespace = "AcmeHealth/Security"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "kms_key_deletion" {
  alarm_name          = "${local.name_prefix}-kms-deletion-alarm-${local.suffix}"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "KMSKeyDeletionCount"
  namespace           = "AcmeHealth/Security"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "CMMC SC.L2-3.13.10: Alert on CMK deletion or disablement"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  tags = {
    Purpose = "ComplianceMonitoring"
  }
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  alarm_name          = "${local.name_prefix}-lambda-errors-${local.suffix}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 60
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "CMMC SI.L2-3.14.6: Lambda error rate spike — possible integrity issue"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    FunctionName = aws_lambda_function.intake.function_name
  }

  tags = {
    Purpose = "ComplianceMonitoring"
  }
}

######################################################################
# EventBridge Rules — detect S3 policy drift (CMMC AC.L2-3.1.5)
######################################################################

resource "aws_cloudwatch_event_rule" "s3_policy_change" {
  name        = "${local.name_prefix}-s3-policy-change-${local.suffix}"
  description = "CMMC AC.L2-3.1.5: Detect S3 bucket policy modifications"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl"]
    }
  })

  tags = {
    Purpose = "ComplianceMonitoring"
  }
}

resource "aws_cloudwatch_event_target" "s3_policy_change" {
  rule      = aws_cloudwatch_event_rule.s3_policy_change.name
  target_id = "SNSAlert"
  arn       = aws_sns_topic.alerts.arn
}

resource "aws_cloudwatch_event_rule" "iam_policy_change" {
  name        = "${local.name_prefix}-iam-policy-change-${local.suffix}"
  description = "CMMC AC.L2-3.1.5: Detect IAM role/policy modifications"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["PutRolePolicy", "AttachRolePolicy", "DetachRolePolicy", "CreatePolicyVersion"]
    }
  })

  tags = {
    Purpose = "ComplianceMonitoring"
  }
}

resource "aws_cloudwatch_event_target" "iam_policy_change" {
  rule      = aws_cloudwatch_event_rule.iam_policy_change.name
  target_id = "SNSAlert"
  arn       = aws_sns_topic.alerts.arn
}

######################################################################
# SNS topic policy — allow EventBridge + CloudWatch to publish
######################################################################

resource "aws_sns_topic_policy" "alerts" {
  arn = aws_sns_topic.alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudWatchAlarms"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      },
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.alerts.arn
      }
    ]
  })
}
