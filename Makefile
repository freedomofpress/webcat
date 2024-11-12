SUBDIRS = extension submission_server transparency_server

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	rm -rf dists/*

deploy: all	
	cd deploy/infra && terraform init
	cd deploy/infra && terraform apply -auto-approve