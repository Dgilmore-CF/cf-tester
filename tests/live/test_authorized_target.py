import os

import pytest

from modules.http_engine import AiohttpEngine, HTTPMethod


@pytest.mark.live
async def test_authorized_target_health_check():
    target = os.environ.get("CF_TEST_TARGET")
    if not target:
        pytest.skip("CF_TEST_TARGET is not configured")

    engine = AiohttpEngine()
    try:
        response = await engine.request(target, HTTPMethod.GET, timeout=10)
    finally:
        await engine.close()

    assert response.error is None
    assert response.status_code > 0


@pytest.mark.destructive
def test_destructive_lane_requires_explicit_harness():
    pytest.skip("High-volume tests must be run manually through the authorized CLI")
