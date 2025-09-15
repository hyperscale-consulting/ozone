import cfnlint

from hyperscale.ozone.s3 import LocalAccessLogsBucket


def test_local_access_logs_bucket():
    lalb = LocalAccessLogsBucket()
    t = lalb.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
    d = t.to_dict()
    params = d["Parameters"]
    assert "CentralS3AccessLogsBucket" in params
    assert "LogArchiveAccount" in params

    resources = d["Resources"]
    assert "AccessLogsBucket" in resources
