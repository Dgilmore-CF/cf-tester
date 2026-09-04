import pytest

from modules.config import Config
from modules.ddos_simulator import DDoSAttackType, DDoSSimulator, DDoSTestResult
from modules.http_engine import HTTPResponse


class FakeEngine:
    def __init__(self):
        self.requests = []

    async def request(self, url, method, **kwargs):
        self.requests.append((url, method, kwargs))
        return HTTPResponse(200, {}, "ok", 0.1, url, cf_ray="ray")

    async def close(self):
        pass


def wave(requests, average, duration):
    return DDoSTestResult(
        DDoSAttackType.HTTP_GET_FLOOD,
        "https://example.com",
        requests,
        requests,
        0,
        0,
        0,
        average,
        average,
        average,
        requests / duration,
        duration,
        False,
    )


@pytest.mark.unit
def test_wave_average_is_weighted_by_request_count():
    simulator = DDoSSimulator(FakeEngine(), Config(targets=["example.com"]))

    combined = simulator._combine_wave_results(
        DDoSAttackType.HTTP_GET_FLOOD,
        "https://example.com",
        [wave(1, 1.0, 1.0), wave(3, 3.0, 1.0)],
    )

    assert combined.avg_response_time == pytest.approx(2.5)
    assert combined.requests_per_second == pytest.approx(2.0)


@pytest.mark.unit
def test_challenged_response_is_not_double_counted_as_blocked_or_successful():
    simulator = DDoSSimulator(FakeEngine(), Config(targets=["example.com"]))
    challenged = HTTPResponse(
        200, {}, "challenge", 0.1, "https://example.com",
        blocked=True, challenge_presented=True,
    )

    result = simulator._compile_results(
        DDoSAttackType.HTTP_GET_FLOOD,
        "https://example.com",
        [challenged],
        1.0,
    )

    assert result.challenged_requests == 1
    assert result.blocked_requests == 0
    assert result.successful_requests == 0


@pytest.mark.unit
@pytest.mark.parametrize(
    ("method_name", "attack_type"),
    [
        ("_http_get_flood", DDoSAttackType.HTTP_GET_FLOOD),
        ("_http_post_flood", DDoSAttackType.HTTP_POST_FLOOD),
    ],
)
async def test_http_floods_compile_responses(method_name, attack_type):
    engine = FakeEngine()
    simulator = DDoSSimulator(
        engine,
        Config(targets=["example.com"], request_count=2, concurrency=1),
    )

    result = await getattr(simulator, method_name)(attack_type, "https://example.com")

    assert result.total_requests == 2
    assert result.successful_requests == 2
    assert result.status_code_distribution == {200: 2}
    assert len(engine.requests) == 2
