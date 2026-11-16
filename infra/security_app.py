import json
from pathlib import Path

import aws_cdk as cdk

from stacks.product_security import ProductSecurityStack


app = cdk.App()
binding_file = app.node.try_get_context("security_binding")
if not binding_file:
    raise ValueError("supply --context security_binding=/absolute/path/to/security-binding.json")
binding = json.loads(Path(binding_file).read_text())
ProductSecurityStack(app, "GogcliProductSecurity", binding=binding,
    env=cdk.Environment(account=binding["account_id"], region=binding["region"]),
    synthesizer=cdk.CliCredentialsStackSynthesizer())
app.synth()
