DIST := ../../dist
OUT  := $(DIST)/webcat-lib-test.zip

all:
	$(MAKE) -C ../../extension package-lib-test
	npm ci
	npm install --no-save ../../dist/webcat-lib-test.tgz
	npx vite build
	cp manifest.json dist/
	mkdir -p dist/webcat/hooks
	cp -r node_modules/@freedomofpress/webcat/data node_modules/@freedomofpress/webcat/icons node_modules/@freedomofpress/webcat/pages dist/webcat/
	cp node_modules/@freedomofpress/webcat/dist/hooks/content.js dist/webcat/hooks/
	rm -f $(OUT) && cd dist && zip -qr $(abspath $(OUT)) .

clean:
	rm -rf node_modules dist
