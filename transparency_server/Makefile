SHELL 			:=	/bin/bash

PROTO_OUT		:=	trillian_proto
TRILLIAN_HOME 	:=	build/trillian

TRILLIAN_PORT	:=	8090
TRILLIAN_HOST	:=	127.0.0.1
DATABASE		:=	build/webcat.db

PUBLICKEY		:=	build/pubkey.pem
PRIVATEKEY		:=	build/privkey.pem

install-deps:
	sudo apt install python3-venv build-essential tmux;

build-venv:
	python3 -m venv venv;
	( \
		source venv/bin/activate; \
		pip3 install -r requirements.txt; \
	)

generate-key:
	( \
		source venv/bin/activate; \
		python3 -c $$'from joserfc.jwk import ECKey\nkey=ECKey.generate_key()\nwith open("${PRIVATEKEY}", "wb") as f: f.write(key.as_bytes()); from cryptography.hazmat.primitives import serialization\nwith open("${PUBLICKEY}", "wb") as f: f.write(key.public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))' \
	)

get-trillian:
	@echo cloning Trillian
	git clone https://github.com/google/trillian build/trillian

start-trillian:
	@echo Starting Trillian containers in tmux
	tmux new-session -d -s trillian 'docker-compose -f ${TRILLIAN_HOME}/examples/deployment/docker-compose.yml up'
	@echo Waiting 60 seconds for Trillian to bootstrap
	sleep 60

build-proto: clean build-venv get-trillian
	mkdir -p ${PROTO_OUT}
	( \
		source venv/bin/activate; \
		python3 -m grpc_tools.protoc -I${TRILLIAN_HOME} -I${TRILLIAN_HOME}/third_party/googleapis/ --python_out=${PROTO_OUT} --pyi_out=${PROTO_OUT} --grpc_python_out=${PROTO_OUT} google/rpc/status.proto trillian.proto trillian_log_api.proto trillian_admin_api.proto; \
	)
	# Silly hack to automatically pack it as a python module
	sed -i 's/^import .*_pb2 as/from . \0/' ${PROTO_OUT}/*.py
	sed -i 's/from google\.rpc/from \.google\.rpc/g' ${PROTO_OUT}/*.py
	for i in ${PROTO_OUT}/*_grpc.py; do \
		file=$$(echo "$$i" | cut -d / -f2 | cut -d . -f 1); \
		echo "from . import $$file" >> ${PROTO_OUT}/__init__.py; \
	done

run: build-proto start-trillian generate-key
	( \
		source venv/bin/activate; \
		TRILLIAN_HOST=127.0.0.1 TRILLIAN_PORT=8090 PUBLICKEY=${PUBLICKEY} DATABASE=${DATABASE} flask --app webcat_log/api.py run --host 0.0.0.0 \
	)

clean:
	rm -rf venv
	rm -rf build
	rm -rf ${PROTO_OUT}
	rm -rf __pycache__
	find . -name "*.pyc" -exec rm -f {} \;
