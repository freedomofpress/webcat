DIST := ../../dist
OUT  := $(DIST)/webcat-lib-test.zip

all:
	$(MAKE) -C ../../extension package-lib-test
	rm -rf node_modules/webcat
	npm install --no-package-lock
	npx vite build
	cp manifest.json dist/
	mkdir -p dist/webcat/hooks
	cp -r node_modules/webcat/data node_modules/webcat/icons node_modules/webcat/pages dist/webcat/
	cp node_modules/webcat/dist/hooks/content.js dist/webcat/hooks/
	rm -f $(OUT) && cd dist && zip -qr $(abspath $(OUT)) .

clean:
	rm -rf node_modules dist
