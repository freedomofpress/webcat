all: package

install:
	npm install

package: install
	PACKAGE_OUT=../dist/webcat-extension.zip npm run package
	PACKAGE_OUT=../dist/webcat-extension-test.zip npm run package:test


cleanup:
	rm -rf dist/*

clean: cleanup
	rm -rf node_modules