import pytest

from modules.config import Config


@pytest.mark.unit
def test_target_urls_are_normalized():
    config = Config(targets=["example.com", "http://localhost:8080"])

    assert config.get_target_urls() == ["https://example.com", "http://localhost:8080"]


@pytest.mark.unit
@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"targets": []}, "At least one target"),
        ({"request_count": 0}, "Request count"),
        ({"concurrency": 0}, "Concurrency"),
        ({"ddos_attack_type": 16}, "DDoS attack type"),
        ({"follow_redirects": "true"}, "Follow redirects"),
        ({"max_redirects": 0}, "Maximum redirects"),
        ({"max_redirects": -1}, "Maximum redirects"),
        ({"max_redirects": True}, "Maximum redirects"),
        ({"max_redirects": 1.5}, "Maximum redirects"),
        ({"http_engine": "selenium", "follow_redirects": False}, "Browser engines"),
        ({"http_engine": "playwright", "max_redirects": 3}, "Browser engines"),
    ],
)
def test_invalid_config_is_rejected(changes, message):
    values = {"targets": ["example.com"], **changes}

    with pytest.raises(ValueError, match=message):
        Config(**values).validate()
