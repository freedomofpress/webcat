### Frontend Architecture
  - Submission Server: API in Lua, insert/edit in database
  - Database Server: PoistgreSQL, manage insertion queue, keeps list info
  - Worker: processes the queue in the Database, does preliminary check + transparency log submission
  - Submission Transparency Log: Trillian
      - **Scope:** `Content-Security-Policy` + `x-sigstore` metadata + `x-webcat` metadata
      - **Source:** operator of deployment (≟ developer of application)
  - Artifact Transparency Log: Trillian
      - **Scope:** manifest
      - **Source:** developer of application (≟ operator of deployment)
  - List Builder: C?
  - CDN Distirbution

![Frontend diagram](https://github.com/freedomofpress/webcat/blob/48d72ad79e2e9ac7a9e98628f6639fa35e75ba63/docs/images/frontend.drawio.png)
