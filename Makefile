SUBDIRS = extension
TEST_DIR = test

.PHONY: all $(SUBDIRS) clean

all: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	rm -rf dist/*

test: extension
	$(MAKE) -C $(TEST_DIR) test

benchmark: extension
	$(MAKE) -C $(TEST_DIR) benchmark