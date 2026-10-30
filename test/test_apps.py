import pytest
from helpers import Server, Hook, UpdateServer
from pytest_check import check
from common import *

@pytest.mark.parametrize("browser", ["firefox", "tbb", "tbb_safer"], indirect=True)
@pytest.mark.parametrize("config_path, bundle_path, root, headers, hooks", [pytest.param(
    "cases/drawio/webcat.config.json",
    "cases/drawio/.well-known/webcat/bundle.json",
    "cases/drawio/webapp",
    {
        "content-security-policy": "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    }, {},
    id="drawio"
)], indirect=["root"])
def test_drawio(browser, server: Server, update_server: UpdateServer, addon_path):
    """
    Tests that the draw.io app works as expected. Checks that the app loads,
    its title is correct, and it displays no error dialog. Loads a diagram and
    checks the title and error dialog agin, and confirms the diagram's
    rendered text content matches expectations.
    """
    server.hooks["/.well-known/webcat/bundle.json"] = Hook(open("cases/drawio/.well-known/webcat/bundle.json", "rb").read(), type="application/json")
    browser.install_extension(addon_path)
    update_server.wait_for_update()

    def error():
        return browser.execute("Array.from(document.querySelectorAll('.geDialog>div>div:not(:last-child)')).map(e => e.textContent).join(': ')")

    with server.wait_for(["/images/github-logo.svg"]):
        browser.navigate(f"{server.url()}?dark=0")
    title = browser.execute("document.title")
    check.equal(title, "Untitled Diagram - draw.io")
    check.equal(error(), "")

    with server.wait_for(["/templates/software/class_1.xml"]):
        browser.navigate(f"#U{server.url()}/templates/software/class_1.xml")
    title = browser.execute("document.title")
    check.equal(title, "class_1.xml - draw.io")
    check.equal(error(), "")
    content = browser.execute("document.querySelector('.geDiagramContainer')?.textContent")
    check.is_in(
        "Classname"
        "+ field: type"
        "+ field: type"
        "+ field: type"
        "+ field: type"
        "+ field: type"
        "+ method(type): type"
        "+ method(type): type",
        content)
