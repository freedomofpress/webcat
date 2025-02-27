## Transparency server
### Depends on (debian)
 * git
 * docker
 * python3-venv

### How to

```
make run
```

This command will:
 * Download Trillian
 * Build the gRPC and protobuf python dependencies
 * Start Trillian in Docker
 * Run the Trillian personality

### Documentation
As suggested in the official Trillian documentation, no core modification are needed to Trillian. Instead, a personality is written around it: enforces leaves compliance, offers REST endpoints and so on.

### Configuration
The personality is a web set of REST API that act as an HTTP frontend to the unmodified, backed Trillian.

It should be configured with the following environment variables:
