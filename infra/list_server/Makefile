# Makefile for domain-verifier project

# Name of the SQLite database file
DB_FILE = submissions.db

# Output directories for built binaries
BIN_DIR = bin
API_BIN = $(BIN_DIR)/api
PROC_BIN = $(BIN_DIR)/processor
LOGS_DIR = logs

TEST_KEY = sigsum.key
TEST_POLICY = sigsum.policy.test

# Default target: build both binaries
all: package

# Build the REST API and background processor binaries.
build:
	@mkdir -p $(BIN_DIR)
	@echo "Building API binary..."
	go build -o $(API_BIN) ./api
	@echo "Building Processor binary..."
	go build -o $(PROC_BIN) ./processor

# Clean the database file and built binaries.
clean: kill
	@echo "Cleaning up..."
	@rm -f $(DB_FILE)
	@rm -rf $(BIN_DIR)
	@rm -rf $(LOGS_DIR)
	@rm -rf $(TEST_KEY)*

# Run the REST API server directly using go run.
run-api:
	@echo "Running API server on http://localhost:8080 ..."
	go run ./api/main_api.go

# Run the background processor directly using go run.
run-processor:
	@echo "Running background processor..."
	go run ./processor/main_processor.go

# Run both API and processor concurrently.
# Note: This simple target uses background execution.
run-test:
	@echo "Running API server and background processor concurrently..."
	@mkdir -p $(LOGS_DIR)
	@nohup go run ./api/main_api.go > $(LOGS_DIR)/api.log 2>&1 &
	@SIGSUM_LOG_POLICY_PATH=$(TEST_POLICY) SIGSUM_PRIVATE_KEY_PATH=$(TEST_KEY) nohup go run ./processor/main_processor.go > $(LOGS_DIR)/processor.log 2>&1 &
	@echo "API is running on http://localhost:8080"

kill:
	@echo "Killing API and processor processes..."
	@pkill -f "main_api" || true
	@pkill -f "main_processor" || true

package:
	@echo "Building release binaries for linux/amd64 with CGO enabled..."
	@mkdir -p $(BIN_DIR)
	@echo "Building API release binary..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-gnu-gcc go build -ldflags "-s -w" -o $(API_BIN) ./api
	@echo "Building Processor release binary..."
	CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-gnu-gcc go build -ldflags "-s -w" -o $(PROC_BIN) ./processor
	@echo "Zipping release binaries..."
	zip -j ../../dist/webcat-list-server.zip $(API_BIN) $(PROC_BIN)
	@echo "Release package created: webcat-list-server.zip"

.PHONY: all build clean run-api run-processor run-all
