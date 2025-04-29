import os
import pytest

def pytest_addoption(parser):
    parser.addoption(
        "--addon", action="store", default=None,
        help="Path to the webcat test addon zip file"
    )

@pytest.fixture(scope="session")
def addon_path(request):
    raw_path = request.config.getoption("--addon")
    if not raw_path:
        pytest.exit("Error: --addon argument is required.")
    abs_path = os.path.abspath(raw_path)
    if not os.path.exists(abs_path):
        pytest.exit(f"Error: Addon path does not exist: {abs_path}")
    return abs_path
