DIST := ../dist
OUT  := $(DIST)/webcat-extension.zip
OUT_TEST  := $(DIST)/webcat-extension-test.zip

INPUTS := manifest.json dist icons pages
FIXED_MTIME := 198001010000

all: package

install:
	npm install

build:
	npm run build

build-test:
	TESTING=true npm run build

package: install build
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -9 -@ $(OUT)

package-test: install build-test
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -0 -@ $(OUT_TEST)

cleanup:
	rm -rf $(DIST)/*

clean: cleanup
	rm -rf node_modules

