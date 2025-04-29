PACKAGE_NAME = webcat-extension
ZIP_FILE = $(PACKAGE_NAME).zip
TEST_ZIP_FILE = $(PACKAGE_NAME)-test.zip

all: build package cleanup clean

build:
	npm install
	npm run build

package: build
	zip -r ../dist/$(ZIP_FILE) manifest.json dist/bundle.js assets icons pages

test-package:
	TESTING=true npm run build
	zip -r ../dist/$(TEST_ZIP_FILE) manifest.json dist/bundle.js assets icons pages

cleanup:
	rm -f dist/* $(ZIP_FILE) $(TEST_ZIP_FILE)

clean: cleanup
	rm -rf node_modules
