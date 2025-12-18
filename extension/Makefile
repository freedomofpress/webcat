DIST := ../dist
OUT  := $(DIST)/webcat-extension.zip
OUT_TEST  := $(DIST)/webcat-extension-test.zip

INPUTS := manifest.json dist icons pages
FIXED_MTIME := 198001010000

all: package

install:
	npm install

package: install
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -0 -@ $(OUT)

package-test: install
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -0 -@ $(OUT_TEST)

cleanup:
	rm -rf $(DIST)/*

clean: cleanup
	rm -rf node_modules

