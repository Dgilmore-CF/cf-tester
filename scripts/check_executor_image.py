"""Verify idle startup/signing in the release image, with Docker networking disabled."""
import asyncio
import hashlib
import hmac
from pathlib import Path
import tempfile
import time

import httpx
from cf_tester_service import create_app


async def check():
    key = "synthetic-image-smoke-key-not-a-secret-1234567890"

    class InertRunner:
        async def run(self, *args):
            raise AssertionError("Image smoke must never execute a run")

    with tempfile.TemporaryDirectory() as directory:
        app = create_app(key=key, state_dir=Path(directory) / "state", runner=InertRunner())
        async with app.router.lifespan_context(app):
            nonce, timestamp = "1" * 32, str(int(time.time()))
            message = f"{timestamp}\n{nonce}\nGET\n/v1/status\n{hashlib.sha256(b'').hexdigest()}".encode()
            headers = {
                "X-CF-Tester-Timestamp": timestamp,
                "X-CF-Tester-Nonce": nonce,
                "X-CF-Tester-Signature": hmac.new(key.encode(), message, hashlib.sha256).hexdigest(),
            }
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://executor", trust_env=False) as client:
                response = await client.get("/v1/status", headers=headers)
            assert response.status_code == 200
            proof = f"{nonce}\n200\n{hashlib.sha256(response.content).hexdigest()}".encode()
            assert hmac.compare_digest(response.headers["X-CF-Tester-Signature"],
                                       hmac.new(key.encode(), proof, hashlib.sha256).hexdigest())
            assert response.json()["mode"] == "remote-waf"
            assert response.json()["enabled"] is True
            assert response.json()["active_run_id"] is None
            assert app.state.store.recent() == []
    print("Executor image startup and signed idle status verified; no runs or target traffic.")


if __name__ == "__main__":
    asyncio.run(check())
