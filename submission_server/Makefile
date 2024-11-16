PACKAGE_NAME = submission-lambda
ZIP_FILE = $(PACKAGE_NAME).zip
LAMBDA_SRC_DIR = .
VENV_DIR = .venv

all: venv install zip cleanup clean

venv:
	python3 -m venv $(VENV_DIR)

install:
	. $(VENV_DIR)/bin/activate && pip install -r requirements.txt -t package

zip:
	rm -f $(ZIP_FILE)
	cd package && zip -r ../$(ZIP_FILE) .
	zip -g $(ZIP_FILE) $(LAMBDA_SRC_DIR)/*.py $(LAMBDA_SRC_DIR)/schema.sql
	# Let's copy it back to the global dists for the project
	cp $(ZIP_FILE) ../dist/

clean:
	rm -rf $(ZIP_FILE) package $(VENV_DIR)

cleanup:
	rm -rf package .venv
