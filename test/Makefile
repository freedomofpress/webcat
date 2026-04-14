VENV=.venv
PYTHON=$(VENV)/bin/python
PIP=$(VENV)/bin/pip
PYTEST=$(VENV)/bin/pytest

TESTARGS ?= --addon ../dist/webcat-extension-test.zip
BENCHARGS ?= --iterations 5

ifdef HEADLESS
	TESTARGS += --headless
endif

.PHONY: all venv install test clean

all: test

venv:
	@test -d $(VENV) || python3 -m venv $(VENV)

install: venv
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test: install
	$(PYTEST) -v tests.py $(TESTARGS)

benchmark: install
	$(PYTEST) -v benchmarks.py $(TESTARGS) $(BENCHARGS)

clean:
	rm -rf $(VENV) __pycache__ .pytest_cache
