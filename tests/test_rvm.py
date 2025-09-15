import cfnlint

from hyperscale.ozone.rvm import RoleVendingMachine
from hyperscale.ozone.rvm import WorkflowRole


def test_rvm():
    rvm = RoleVendingMachine()
    t = rvm.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "GitHubRepo" in params
    assert "RvmPipelineBucketAccessLogBucket" in params
    assert "GitHubOidcProviderArn" in params

    resources = d["Resources"]
    assert "RvmPipelineBucket" in resources


def test_rvm_workflow_role():
    wfr = WorkflowRole()
    t = wfr.create_template()
    errors = cfnlint.lint(t.to_json())
    assert not errors
    d = t.to_dict()
    assert "RvmAccount" in d["Parameters"]
    assert "RvmWorkflowRole" in d["Resources"]
