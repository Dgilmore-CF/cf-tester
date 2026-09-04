import pytest

from modules.http_engine import HTTPMethod, PlaywrightEngine, SeleniumEngine


@pytest.mark.browser
async def test_playwright_smoke(local_server):
    engine = PlaywrightEngine()
    try:
        response = await engine.request(local_server, HTTPMethod.GET)
    finally:
        await engine.close()
    assert response.status_code == 200


@pytest.mark.browser
async def test_selenium_smoke(local_server):
    engine = SeleniumEngine()
    try:
        response = await engine.request(local_server, HTTPMethod.GET)
    finally:
        await engine.close()
    assert response.status_code == 200
