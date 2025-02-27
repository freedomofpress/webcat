BIN_DIR = bin
LIST_BUILDER_BIN = $(BIN_DIR)/webcat-list-builder

all: package

clean:
	@rm -rf $(BIN_DIR)
	@rm -rf pub/*
	@rm -rf *.key *.pub

package:
	@echo "Building release binary for linux/amd64 with CGO enabled..."
	@mkdir -p $(BIN_DIR)
	@echo "Building List Builder binary..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-gnu-gcc go build -ldflags "-s -w" -o $(LIST_BUILDER_BIN) main.go
	@echo "Zipping release binary..."
	zip -j $(DIST_DIR)/webcat-build-server.zip $(LIST_BUILDER_BIN)
	@echo "Release package created: ../../webcat-build-server.zip"

.PHONY: package