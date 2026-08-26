"""
Suite-wide pytest fixtures.
"""
import pytest


@pytest.fixture(autouse=True)
def _isolate_github_step_summary(monkeypatch, tmp_path):
    """GITHUB_STEP_SUMMARY is set ambiently by GitHub Actions for every job
    step -- including the `pytest` step itself (see assay.yml's `build`
    job). Many tests call cli.verify's main()/_write_github_step_summary()
    directly against fixtures that are *deliberately* FAILED/GATED (bad
    RCS, malformed envelopes, ...); without this, any such test that
    doesn't individually save/redirect/restore that env var appends its
    fixture-derived report straight into the real CI job's own Step
    Summary -- unrelated noise from the test suite showing up as if it
    were reporting on that job itself (this is exactly what produced the
    "job still shows passed, first execution shows failed" confusion
    after fix/verdict-heading-vocabulary reached main: the pytest step's
    own summary, not any real verify run, was accumulating FAILED/GATED
    blocks from RCS=50/RCS=90 test fixtures).

    Redirects every test, unconditionally, to its own function-scoped
    throwaway file instead of leaving GITHUB_STEP_SUMMARY pointed at
    whatever's ambient -- so no test, present or future, can leak into a
    real job's summary again, regardless of whether that test's author
    remembered to handle this individually. A test that wants to assert
    against the written file (see StepSummaryWriterTests in
    test_source_track_and_build_l3.py) can still safely override this
    within its own body; monkeypatch restores the true original value
    after the test either way."""
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(tmp_path / "step-summary.md"))
