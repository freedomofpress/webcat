DIST := ../dist
OUT  := $(DIST)/webcat-extension.zip
OUT_TEST  := $(DIST)/webcat-extension-test.zip
OUT_LIB_TEST := $(DIST)/webcat-lib-test.tgz

INPUTS := manifest.json dist/bundle.js dist/hooks/content.js icons pages data _locales
FIXED_MTIME := 198001010000

all: package package-test

install:
	npm install

build:
	npm run build

build-test:
	VITE_TESTING=true npm run build

fetch-data:
	mkdir -p data
	curl https://webcat.freedom.press/list.json -o data/list.json
	curl https://webcat.freedom.press/block.json -o data/block.json

package: install build fetch-data
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -9 -@ $(OUT)

package-test: install build-test fetch-data
	find $(INPUTS) -type f -exec touch -h -t $(FIXED_MTIME) {} +
	TZ=UTC find $(INPUTS) -type f \
	  | LC_ALL=C sort \
	  | zip -X -0 -@ $(OUT_TEST)

# npm package built with the test flag, consumed by ../test/libext
package-lib-test: install fetch-data
	rm -f $(DIST)/webcat-*.tgz
	VITE_TESTING=true npm pack --pack-destination $(DIST)
	mv $(DIST)/webcat-*.tgz $(OUT_LIB_TEST)

cleanup:
	rm -rf $(DIST)/* data/

clean: cleanup
	rm -rf node_modules

