SHELL 			:=	/bin/bash

TRILLIAN_HOME 	:=	build/trillian

TRILLIAN_PORT	:=	8090
TRILLIAN_HOST	:=	127.0.0.1
DATABASE		:=	build/webcat.db

PUBLICKEY		:=	build/pubkey.pem
PRIVATEKEY		:=	build/privkey.pem

PACKAGE_NAME = transparency-lambda
ZIP_FILE = $(PACKAGE_NAME).zip
LAMBDA_SRC_DIR = webcat_log
DEPS_DIR = package
PROTO_OUT =	$(DEPS_DIR)/trillian_proto
VENV_DIR = .venv

all: venv install zip cleanup clean

# Most of this Makefile has been written for debugging and to run the setup locally
install-deps:
	sudo apt install python3-venv build-essential tmux;

venv:
	python3 -m venv $(VENV_DIR);

install:
	source ${VENV_DIR}/bin/activate && pip3 install -r requirements.txt -t $(DEPS_DIR)

generate-key:
	( \
		source ${VENV_DIR}/bin/activate; \
		PYTHONPATH=package python3 -c $$'from joserfc.jwk import ECKey\nkey=ECKey.generate_key()\nwith open("${PRIVATEKEY}", "wb") as f: f.write(key.as_bytes()); from cryptography.hazmat.primitives import serialization\nwith open("${PUBLICKEY}", "wb") as f: f.write(key.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))' \
	)

get-trillian:
	@echo cloning Trillian
	git clone https://github.com/google/trillian build/trillian

start-trillian:
	@echo Starting Trillian containers in tmux
	tmux new-session -d -s trillian 'docker-compose -f ${TRILLIAN_HOME}/examples/deployment/docker-compose.yml up'
	@echo Waiting 60 seconds for Trillian to bootstrap
	sleep 60

build-proto: clean venv get-trillian
	mkdir -p ${PROTO_OUT}
	( \
		source ${VENV_DIR}/bin/activate; \
		PYTHONPATH=package python3 -m grpc_tools.protoc -I${TRILLIAN_HOME} -I${TRILLIAN_HOME}/third_party/googleapis/ --python_out=${PROTO_OUT} --pyi_out=${PROTO_OUT} --grpc_python_out=${PROTO_OUT} google/rpc/status.proto trillian.proto trillian_log_api.proto trillian_admin_api.proto; \
	)
	# Silly hack to automatically pack it as a python module
	sed -i '' 's/^import .*_pb2 as/from . \0/' ${PROTO_OUT}/*.py
	sed -i '' 's/from google\.rpc/from \.google\.rpc/g' ${PROTO_OUT}/*.py

	# Create __init__.py and append imports for gRPC files
	for i in ${PROTO_OUT}/*_grpc.py; do \
		file=$$(basename "$$i" | cut -d . -f 1); \
		echo "from . import $$file" >> ${PROTO_OUT}/__init__.py; \
	done

run: build-proto start-trillian generate-key
	( \
		source ${VENV_DIR}/bin/activate; \
		PYTHONPATH=package TRILLIAN_HOST=127.0.0.1 TRILLIAN_PORT=8090 PUBLICKEY=${PUBLICKEY} DATABASE=${DATABASE} flask --app webcat_log/api.py run --host 0.0.0.0 \
	)

zip:
	rm -f $(ZIP_FILE)
	cd package && zip -r ../$(ZIP_FILE) .
	zip -g $(ZIP_FILE) $(LAMBDA_SRC_DIR)/*.py
	# Let's copy it back to the global dists for the project
	cp $(ZIP_FILE) ../dist/

cleanup:
	rm -f $(ZIP_FILE)

clean:
	rm -rf $(VENV_DIR)
	rm -rf $(DEPS_DIR)
	rm -rf build
	rm -rf ${PROTO_OUT}
	rm -rf __pycache__
	find . -name "*.pyc" -exec rm -f {} \;
