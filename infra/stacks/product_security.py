import re

from aws_cdk import CfnOutput, Duration, RemovalPolicy, Stack
from aws_cdk import aws_iam as iam


class ProductSecurityStack(Stack):
    def __init__(self, scope, construct_id, *, binding, **kwargs):
        super().__init__(scope, construct_id, **kwargs)
        account, region = self.account, self.region
        prefix = binding["role_prefix"]
        if not re.fullmatch(r"gogcli-[a-z0-9-]+", prefix):
            raise ValueError("role_prefix must start with gogcli- and contain lowercase letters, digits or hyphens")
        principal = binding["principal_arn"]
        if not re.fullmatch(r"arn:aws:iam::[0-9]{12}:(?:user|role)/[A-Za-z0-9_+=,.@/-]+", principal):
            raise ValueError("principal_arn must identify one IAM user or role")
        stack_name = binding["application_stack_name"]
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", stack_name) or stack_name == self.stack_name:
            raise ValueError("application_stack_name must identify a separate application stack")
        parameter = f"arn:aws:ssm:{region}:{account}:parameter{binding['ssm_prefix']}"
        app_stack = f"arn:aws:cloudformation:{region}:{account}:stack/{stack_name}/*"
        resources = binding.get("application_resources")
        discovered = resources is not None
        resources = resources or {
            "table_arn": f"arn:aws:dynamodb:{region}:{account}:table/{stack_name}-*",
            "download_bucket_arn": f"arn:aws:s3:::{stack_name.lower()}-*",
            "queue_arns": [f"arn:aws:sqs:{region}:{account}:{stack_name}-*"],
            "api_id": "*", "api_key_id": "*", "event_source_mapping_arns": [],
        }
        if discovered:
            for name in ("table_arn", "download_bucket_arn", "api_id", "api_key_id"):
                if not resources[name] or any(value in resources[name] for value in "*?"):
                    raise ValueError(f"application_resources.{name} must identify one resource")
            for name in ("queue_arns", "event_source_mapping_arns"):
                if not resources[name] or any(not arn or "*" in arn or "?" in arn for arn in resources[name]):
                    raise ValueError(f"application_resources.{name} must identify exact resources")
        table = resources["table_arn"]
        bucket = resources["download_bucket_arn"]
        queues = resources["queue_arns"]
        api_id, stage = resources["api_id"], binding["stage"]
        api = f"arn:aws:execute-api:{region}:{account}:{api_id}/{stage}"
        api_control = f"arn:aws:apigateway:{region}::"
        log_groups = [f"arn:aws:logs:{region}:{account}:log-group:/aws/lambda/{prefix}-*:*",
            f"arn:aws:logs:{region}:{account}:log-group:{stack_name}-*:*",
            f"arn:aws:logs:{region}:{account}:log-group:API-Gateway-Execution-Logs_{api_id}/*:*"]
        log_groups += [arn.removesuffix(":*") for arn in log_groups]
        functions = [f"arn:aws:lambda:{region}:{account}:function:{prefix}-{name}" for name in ("proxy", "onboarding")]
        runtime_arns = {name: f"arn:aws:iam::{account}:role/{prefix}-{name}" for name in ("proxy", "onboarding", "apigw-logs")}
        key = binding["ssm_key_arn"]
        kms_condition = {"StringEquals": {"kms:ViaService": f"ssm.{region}.amazonaws.com"}}
        ceilings = {
            "proxy": [
                statement(["logs:CreateLogStream", "logs:PutLogEvents"], log_groups),
                statement(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], [bucket + "/downloads/*"]),
                statement(["dynamodb:GetItem", "dynamodb:Scan"], [table]),
                statement(["ssm:GetParameter", "ssm:GetParameters"], [parameter + suffix for suffix in ("/allow/*", "/google/accounts/*", "/policy/*")]),
                statement(["kms:Decrypt"], [key], conditions=kms_condition),
            ],
            "onboarding": [
                statement(["logs:CreateLogStream", "logs:PutLogEvents"], log_groups),
                statement(["dynamodb:BatchGetItem", "dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:Query", "dynamodb:GetItem", "dynamodb:Scan", "dynamodb:ConditionCheckItem", "dynamodb:BatchWriteItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:DescribeStream"], [table, table + "/stream/*", table + "/index/*"]),
                statement(["dynamodb:ListStreams"], ["*"]),
                statement(["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"], queues),
                statement(["ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter"], [parameter + "/*"]),
                statement(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], [key], conditions=kms_condition),
                statement(["apigateway:GET"], [api_control + "/apikeys/" + resources["api_key_id"]]),
                statement(["execute-api:Invoke"], [api + "/GET/" + path for path in ("gmail/*", "drive/v3/*", "calendar/v3/*")]),
            ],
            "apigw-logs": [statement(["logs:CreateLogGroup", "logs:CreateLogStream", "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:PutLogEvents", "logs:GetLogEvents", "logs:FilterLogEvents"], ["*"])],
        }
        boundaries = {}
        for name, statements in ceilings.items():
            boundaries[name] = iam.ManagedPolicy(self, name + "Boundary", managed_policy_name=f"{prefix}-{name}-boundary",
                statements=statements)
        trust = iam.ArnPrincipal(principal)
        roles = {name: iam.Role(self, name.title(), role_name=f"{prefix}-{name}", assumed_by=trust,
            max_session_duration=Duration.hours(1)) for name in ("deployment", "inspection", "operation")}
        deploy = roles["deployment"]
        deploy.add_to_policy(statement(["cloudformation:CreateStack", "cloudformation:UpdateStack", "cloudformation:DeleteStack", "cloudformation:CreateChangeSet", "cloudformation:DescribeChangeSet", "cloudformation:ExecuteChangeSet", "cloudformation:DeleteChangeSet", "cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents", "cloudformation:DescribeStackResources", "cloudformation:ListStackResources", "cloudformation:GetTemplate", "cloudformation:GetStackPolicy", "cloudformation:SetStackPolicy", "cloudformation:ContinueUpdateRollback", "cloudformation:CancelUpdateStack"], [app_stack]))
        deploy.add_to_policy(statement(["cloudformation:ValidateTemplate", "cloudformation:GetTemplateSummary"], ["*"]))
        for name, arn in runtime_arns.items():
            deploy.add_to_policy(statement(["iam:CreateRole", "iam:PutRolePermissionsBoundary"], [arn],
                conditions={"ArnEquals": {"iam:PermissionsBoundary": boundaries[name].managed_policy_arn}}))
            deploy.add_to_policy(statement(["iam:GetRole", "iam:DeleteRole", "iam:GetRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy", "iam:ListRolePolicies", "iam:ListAttachedRolePolicies", "iam:TagRole", "iam:UntagRole"], [arn]))
            deploy.add_to_policy(statement(["iam:PassRole"], [arn], conditions={"StringEquals": {"iam:PassedToService": "apigateway.amazonaws.com" if name == "apigw-logs" else "lambda.amazonaws.com"}}))
        deploy.add_to_policy(statement(["lambda:CreateFunction", "lambda:GetFunction", "lambda:GetFunctionConfiguration", "lambda:UpdateFunctionCode", "lambda:UpdateFunctionConfiguration", "lambda:DeleteFunction", "lambda:AddPermission", "lambda:RemovePermission", "lambda:GetPolicy", "lambda:TagResource", "lambda:UntagResource", "lambda:ListTags"], functions))
        deploy.add_to_policy(statement(["lambda:CreateEventSourceMapping", "lambda:GetEventSourceMapping", "lambda:UpdateEventSourceMapping", "lambda:DeleteEventSourceMapping", "lambda:ListEventSourceMappings"], ["*"], conditions={"ArnEqualsIfExists": {"lambda:FunctionArn": functions}}))
        deploy.add_to_policy(statement(["apigateway:GET", "apigateway:POST", "apigateway:PUT", "apigateway:PATCH", "apigateway:DELETE"], [api_control + "/*"]))
        deploy.add_to_policy(statement(["dynamodb:CreateTable", "dynamodb:UpdateTable", "dynamodb:DeleteTable", "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:UpdateContinuousBackups", "dynamodb:DescribeTimeToLive", "dynamodb:UpdateTimeToLive", "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:ListTagsOfResource"], [f"arn:aws:dynamodb:{region}:{account}:table/{stack_name}-*"]))
        deploy.add_to_policy(statement(["sqs:CreateQueue", "sqs:DeleteQueue", "sqs:SetQueueAttributes", "sqs:GetQueueAttributes", "sqs:GetQueueUrl", "sqs:TagQueue", "sqs:UntagQueue", "sqs:ListQueueTags"], [f"arn:aws:sqs:{region}:{account}:{stack_name}-*"]))
        deploy.add_to_policy(statement(["s3:*"], [bucket, bucket + "/*"]))
        deploy.add_to_policy(statement(["s3:GetBucketLocation", "s3:GetBucketVersioning", "s3:ListBucket"], [binding["asset_bucket_arn"]]))
        deploy.add_to_policy(statement(["s3:GetObject", "s3:GetObjectVersion", "s3:PutObject", "s3:AbortMultipartUpload"], [binding["asset_bucket_arn"] + "/*"]))
        deploy.add_to_policy(statement(["acm:RequestCertificate"], ["*"], conditions={"ForAllValues:StringEquals": {"acm:DomainNames": [binding["public_domain_name"]]}}))
        deploy.add_to_policy(statement(["acm:DescribeCertificate", "acm:DeleteCertificate", "acm:AddTagsToCertificate", "acm:RemoveTagsFromCertificate", "acm:ListTagsForCertificate"], [f"arn:aws:acm:{region}:{account}:certificate/*"]))
        deploy.add_to_policy(statement(["ssm:PutParameter", "ssm:DeleteParameter", "ssm:GetParameters", "ssm:AddTagsToResource", "ssm:RemoveTagsFromResource", "ssm:ListTagsForResource"], [parameter + "/policy/*"]))
        deploy.add_to_policy(statement(["logs:CreateLogGroup", "logs:DeleteLogGroup", "logs:PutRetentionPolicy", "logs:DeleteRetentionPolicy", "logs:TagResource", "logs:UntagResource", "logs:ListTagsForResource"], log_groups))
        deploy.add_to_policy(statement(["logs:DescribeLogGroups", "cloudwatch:DescribeAlarms"], ["*"]))
        deploy.add_to_policy(statement(["cloudwatch:PutMetricAlarm", "cloudwatch:DeleteAlarms", "cloudwatch:TagResource", "cloudwatch:UntagResource", "cloudwatch:ListTagsForResource"], [f"arn:aws:cloudwatch:{region}:{account}:alarm:{stack_name}-*"]))
        inspect = roles["inspection"]
        inspect.add_to_policy(statement(["cloudformation:DescribeStacks", "cloudformation:DescribeStackEvents", "cloudformation:DescribeStackResources", "cloudformation:ListStackResources"], [app_stack, self.stack_id]))
        inspect.add_to_policy(statement(["lambda:ListEventSourceMappings", "logs:DescribeLogGroups", "cloudwatch:GetMetricData", "cloudwatch:GetMetricStatistics", "cloudwatch:ListMetrics", "cloudwatch:DescribeAlarms", "ssm:DescribeParameters"], ["*"]))
        inspect.add_to_policy(statement(["lambda:GetFunctionConcurrency", "lambda:GetFunctionEventInvokeConfig", "lambda:GetPolicy"], functions))
        inspect.add_to_policy(statement(["dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:DescribeTimeToLive"], [table]))
        inspect.add_to_policy(statement(["sqs:GetQueueAttributes"], queues))
        inspect.add_to_policy(statement(["s3:GetBucketLocation", "s3:GetEncryptionConfiguration", "s3:GetBucketPublicAccessBlock", "s3:GetLifecycleConfiguration"], [bucket]))
        inspect.add_to_policy(statement(["apigateway:GET"], [api_control + "/restapis"]))
        if discovered:
            inspect.add_to_policy(statement(["apigateway:GET"], [api_control + f"/restapis/{api_id}", api_control + f"/restapis/{api_id}/stages", api_control + f"/restapis/{api_id}/stages/{stage}"]))
        operation = roles["operation"]
        if discovered:
            operation.add_to_policy(statement(["execute-api:Invoke"], [api + suffix for suffix in ("/*/gmail/*", "/*/drive/v3/*", "/*/upload/drive/v3/*", "/*/resumable/upload/drive/v3/*", "/*/calendar/v3/*", "/GET/proxy/v1/accounts")]))
        if discovered:
            operation.add_to_policy(statement(["ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:PutParameter", "ssm:DeleteParameter", "ssm:DeleteParameters"], [parameter + "/*"]))
        if discovered:
            operation.add_to_policy(statement(["kms:Decrypt", "kms:Encrypt", "kms:GenerateDataKey"], [key], conditions=kms_condition))
        if discovered:
            operation.add_to_policy(statement(["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchGetItem", "dynamodb:BatchWriteItem"], [table, table + "/index/*"]))
        if discovered:
            operation.add_to_policy(statement(["sqs:GetQueueAttributes", "sqs:ReceiveMessage", "sqs:SendMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility"], queues))
        if discovered:
            operation.add_to_policy(statement(["s3:ListBucket"], [bucket]))
        if discovered:
            operation.add_to_policy(statement(["s3:GetObject", "s3:PutObject", "s3:DeleteObject"], [bucket + "/*"]))
        if discovered:
            operation.add_to_policy(statement(["logs:FilterLogEvents", "logs:GetLogEvents", "logs:DescribeLogStreams"], log_groups))
        if discovered:
            operation.add_to_policy(statement(["apigateway:GET"], [api_control + "/apikeys/" + resources["api_key_id"]]))
        if discovered:
            operation.add_to_policy(statement(["lambda:GetEventSourceMapping", "lambda:UpdateEventSourceMapping"], resources["event_source_mapping_arns"]))
        for name, role in roles.items():
            role.apply_removal_policy(RemovalPolicy.RETAIN)
            policy = role.node.try_find_child("DefaultPolicy")
            if policy is not None:
                policy.apply_removal_policy(RemovalPolicy.RETAIN)
            CfnOutput(self, name.title() + "RoleArn", value=role.role_arn)
        for name, boundary in boundaries.items():
            boundary.apply_removal_policy(RemovalPolicy.RETAIN)
            CfnOutput(self, name.replace("-", "").title() + "BoundaryArn", value=boundary.managed_policy_arn)


def statement(actions, resources, **kwargs):
    return iam.PolicyStatement(actions=actions, resources=resources, **kwargs)
