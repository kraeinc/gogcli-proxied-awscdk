import json
import unittest

from aws_cdk import App, Environment
from aws_cdk.assertions import Template

from stacks.product_security import ProductSecurityStack


class ProductSecurityTests(unittest.TestCase):
    def binding(self):
        return dict(role_prefix="gogcli", principal_arn="arn:aws:iam::111111111111:user/operator",
            application_stack_name="GogcliGoogleProxyApi", ssm_prefix="/gogcli-proxy", stage="prd",
            ssm_key_arn="arn:aws:kms:us-east-2:222222222222:key/test-key",
            asset_bucket_arn="arn:aws:s3:::cdk-assets-222222222222-us-east-2",
            public_domain_name="proxy.example.com", public_hosted_zone_id="Z0123456789")

    def template(self, binding):
        app = App()
        stack = ProductSecurityStack(app, "Security", binding=binding,
            env=Environment(account="222222222222", region="us-east-2"))
        return Template.from_stack(stack).to_json()

    def role_statements(self, template, suffix):
        role_id = next(key for key, resource in template['Resources'].items()
            if resource['Type'] == 'AWS::IAM::Role' and resource['Properties']['RoleName'].endswith(suffix))
        return [statement for resource in template['Resources'].values()
            if resource['Type'] == 'AWS::IAM::Policy' and resource['Properties']['Roles'] == [{'Ref': role_id}]
            for statement in resource['Properties']['PolicyDocument']['Statement']]

    def test_bootstrap_creates_roles_and_ceilings_without_operational_access(self):
        template = self.template(self.binding())
        resources = template['Resources']
        roles = [value for value in resources.values() if value['Type'] == 'AWS::IAM::Role']
        self.assertEqual({'gogcli-deployment', 'gogcli-inspection', 'gogcli-operation'},
            {value['Properties']['RoleName'] for value in roles})
        for role in roles:
            self.assertEqual('Retain', role['DeletionPolicy'])
            self.assertEqual([{'Action': 'sts:AssumeRole', 'Effect': 'Allow', 'Principal':
                {'AWS': self.binding()['principal_arn']}}], role['Properties']['AssumeRolePolicyDocument']['Statement'])
        self.assertEqual({'gogcli-internal-proxy-boundary', 'gogcli-internal-onboarding-boundary', 'gogcli-internal-apigw-logs-boundary'},
            {value['Properties']['ManagedPolicyName'] for value in resources.values() if value['Type'] == 'AWS::IAM::ManagedPolicy'})
        self.assertEqual([], self.role_statements(template, '-operation'))
        self.assertNotIn('Jdev', json.dumps(template))

    def test_deployer_cannot_manage_access_roles_or_boundary_policies(self):
        template = self.template(self.binding())
        statements = self.role_statements(template, '-deployment')
        iam_statements = [value for value in statements if any(action.startswith('iam:')
            for action in action_list(value))]
        for statement in iam_statements:
            rendered = json.dumps(statement['Resource'])
            self.assertNotIn('*', rendered)
            self.assertTrue(any(name in rendered for name in ('-internal-proxy', '-internal-onboarding', '-internal-apigw-logs')))
            self.assertFalse(any(action in action_list(statement) for action in (
                'iam:UpdateAssumeRolePolicy', 'iam:DeleteRolePermissionsBoundary', 'iam:CreatePolicy',
                'iam:CreatePolicyVersion', 'iam:AttachRolePolicy')))
            if 'iam:CreateRole' in action_list(statement):
                self.assertIn('iam:PermissionsBoundary', statement['Condition']['ArnEquals'])
            if 'iam:PassRole' in action_list(statement):
                self.assertIn(statement['Condition']['StringEquals']['iam:PassedToService'],
                    ('lambda.amazonaws.com', 'apigateway.amazonaws.com'))
        for statement in statements:
            if any(action.startswith('cloudformation:') for action in action_list(statement)) and statement['Resource'] != '*':
                self.assertIn(':stack/GogcliGoogleProxyApi/*', json.dumps(statement['Resource']))
        self.assertLess(sum(len(json.dumps(value, separators=(',', ':'))) for value in statements), 10240)

    def test_inspection_excludes_payload_secret_code_and_key_actions(self):
        statements = self.role_statements(self.template(self.binding()), '-inspection')
        actions = {action for statement in statements for action in action_list(statement)}
        self.assertFalse(actions & {'lambda:GetFunction', 'lambda:GetFunctionConfiguration', 'lambda:ListFunctions',
            'ssm:GetParameter', 'ssm:GetParameters', 'ssm:GetParametersByPath', 'dynamodb:Scan',
            'dynamodb:GetItem', 's3:GetObject', 'logs:GetLogEvents', 'logs:FilterLogEvents',
            'execute-api:Invoke', 'cloudformation:GetTemplate'})
        for statement in statements:
            if 'apigateway:GET' in action_list(statement):
                self.assertNotIn('*', json.dumps(statement['Resource']))
                self.assertNotIn('/apikeys', json.dumps(statement['Resource']))
                self.assertNotIn('/integrations', json.dumps(statement['Resource']))

    def test_discovered_resources_enable_only_product_operation_access(self):
        binding = self.binding()
        binding['application_resources'] = dict(table_arn='arn:aws:dynamodb:us-east-2:222222222222:table/state',
            download_bucket_arn='arn:aws:s3:::product-downloads', queue_arns=['arn:aws:sqs:us-east-2:222222222222:verification'],
            api_id='abcdefghij', api_key_id='key-id',
            event_source_mapping_arns=['arn:aws:lambda:us-east-2:222222222222:event-source-mapping:example'])
        statements = self.role_statements(self.template(binding), '-operation')
        self.assertTrue(statements)
        for statement in statements:
            self.assertFalse(any(action.startswith(('iam:', 'cloudformation:')) for action in action_list(statement)))
        invokes = [statement for statement in statements if 'execute-api:Invoke' in action_list(statement)]
        self.assertEqual(1, len(invokes))
        self.assertEqual(6, len(invokes[0]['Resource']))
        self.assertTrue(all(':abcdefghij/prd/' in resource for resource in invokes[0]['Resource']))

    def test_wildcard_principals_are_rejected(self):
        binding = self.binding()
        binding['principal_arn'] = 'arn:aws:iam::111111111111:role/*'
        with self.assertRaises(ValueError):
            self.template(binding)


def action_list(statement):
    actions = statement['Action']
    return [actions] if isinstance(actions, str) else actions
