This folder contains components that are no longer in use. Before migrating to Sigsum, the system relied on a dedicated Trillian log server with a custom-built personality. I also developed Python bindings for Trillian, which are still available.

The infrastructure has since been greatly simplified by no longer running its own transparency server, making the existing Terraform setup unnecessary and now deprecated.
