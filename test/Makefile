VENV=.venv
PYTHON=$(VENV)/bin/python
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

.PHONY: all venv install test clean

all: test

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test: install
	$(PYTEST) -v tests.py --addon ../dist/webcat-extension-test.zip

benchmark: install
	$(PYTHON) benchmarks.py --addon ../dist/webcat-extension-test.zip --iterations 5

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache
