PACKAGE_NAME = webcat-extension
ZIP_FILE = $(PACKAGE_NAME).zip

all: build package cleanup clean

build:
	npm install
	npm run build

beautify:
	npx prettier . --write

lint:
	npx eslint . --ignore-pattern "dist/*" --ignore-pattern "hooks/*" --ignore-pattern "pages/*"

package: build
	zip -r $(ZIP_FILE) manifest.json dist/bundle.js assets hooks icons pages
	cp $(ZIP_FILE) ../dist/

cleanup:
	rm -f dist/* $(ZIP_FILE)

clean: cleanup
	rm -rf node_modules
