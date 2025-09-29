import cfnlint

from hyperscale.ozone.pipelines import LandingZoneConfigurationPipeline


def test_lz_pipeline():
    pipeline = LandingZoneConfigurationPipeline()
    t = pipeline.create_template()
    errors = cfnlint.lint(
        t.to_json(),
    )
    assert not errors
