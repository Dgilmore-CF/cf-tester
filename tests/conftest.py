import pytest
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def pytest_addoption(parser):
    parser.addoption("--run-browser", action="store_true", default=False)
    parser.addoption("--run-live", action="store_true", default=False)
    parser.addoption("--run-destructive", action="store_true", default=False)


def pytest_collection_modifyitems(config, items):
    options = {
        "browser": "--run-browser",
        "live": "--run-live",
        "destructive": "--run-destructive",
    }
    for item in items:
        for marker, option in options.items():
            if marker in item.keywords and not config.getoption(option):
                item.add_marker(pytest.mark.skip(reason=f"requires {option}"))


class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, format, *args):
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    thread.join()
    server.server_close()
